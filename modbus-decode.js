module.exports = function (RED) {

    function Decode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        // 获取输入的参数
        let columns = config.columns.map(col => {
            //缓存算术表达式
            let arithmetic = col.Arithmetic.trim();
            if (arithmetic && !ArithmeticCache[arithmetic]) {
                ArithmeticCache[arithmetic] = parseArithmeticTemplate(arithmetic);
            }
            return {
                Key: col.Key,
                Label: col.Label,
                ValueType: col.ValueType,
                Offset: col.Offset !== "" && col.Offset !== undefined ? parseInt(col.Offset, 10) : null,
                Length: col.Length !== "" && col.Length !== undefined ? parseInt(col.Length, 10) : null,
                Arithmetic: arithmetic
            };
        });

        let devices = new Map(config.devices.map(dev => [dev.unitID, {
            topic: dev.topic,
            deviceKey: dev.deviceKey,
            deviceSecret: dev.deviceSecret,
            productKey: dev.productKey,
            productSecret: dev.productSecret
        }]));

        //接收上游节点接收消息,转换数据并发送到下游节点
        node.on('input', function (msg) {
            let device = devices.get(msg.unitId.toString());
            let sendData = {
                "unitId": device ? device.deviceKey || msg.unitId : msg.unitId,
                "data": handleData(msg.responseBuffer, columns)
            }
            let mqttData = {
                topic: device ? device.topic || "" : "",
                payload: {
                    deviceKey: device ? device.deviceKey || msg.unitId : msg.unitId,
                    deviceSecret: device ? device.deviceSecret || "" : "",
                    productKey: device ? device.productKey || "" : "",
                    productSecret: device ? device.productSecret || "" : "",
                    data: {
                        attr: [sendData.data]
                    }
                }
            }
            node.send([{
                payload: sendData
            }, device ? mqttData : sendData])
        });
    }

    const { Buffer } = require('buffer');
    // 缓存已编译的算术表达式函数
    const ArithmeticCache = {};

    /**
     * 解析 vsprintf 表达式并生成可执行模板函数
     * @param {string} arithmetic - vsprintf 格式的表达式
     * @returns {function|null} 返回一个可执行的模板函数，传入参数进行计算；如果解析失败，返回 null
     */
    function parseArithmeticTemplate(arithmetic) {
        const regex = /%(\d+\$)?[-+'# 0]*([*]|\d+)?(\.\d+)?[hlL]?([cCdiouxXeEfgGaAsSpn%])/g;

        let argIndex = 0; // 用于非命名参数的计数
        const argPositions = []; // 存储参数位置
        const argNames = []; // 存储参数名

        // 替换占位符为变量名，并收集参数名
        const template = arithmetic.replace(regex, (match, position) => {
            let index;
            if (position) {
                // 处理形如 `%1$d` 的参数索引
                index = parseInt(position) - 1;
            } else {
                index = argIndex++;
            }
            argPositions.push(index);
            const argName = `arg${index}`;
            argNames[index] = argName; // 确保参数名按照正确的索引排列
            return argName;
        });

        // 验证表达式的安全性
        if (!isSafeExpression(template)) {
            console.error(`检测到不安全的表达式：${template}`);
            return null;
        }

        // 去除未定义的参数名（可能存在参数跳跃的情况）
        const uniqueArgNames = argNames.filter(name => name !== undefined);

        // 检查表达式是否包含允许的方法调用
        const methodCallPattern = /\.([a-zA-Z_$][0-9a-zA-Z_$]*)\(/g;
        const methodCalls = [...template.matchAll(methodCallPattern)];
        const usesToFixed = methodCalls.some(match => match[1] === 'toFixed');

        // 创建可执行的函数
        try {
            let funcBody;
            if (usesToFixed) {
                // 如果使用了 toFixed 方法，提供安全的 toFixed
                funcBody = `
                    const toFixed = Number.prototype.toFixed.bind(Number.prototype);
                    return ${template};
                `;
            } else {
                // 否则，直接返回表达式结果
                funcBody = `return ${template};`;
            }
            const func = new Function(...uniqueArgNames, funcBody);
            return function (...args) {
                return func(...args);
            };
        } catch (err) {
            console.error(`创建函数时出错，模板：${template}`, err);
            return null;
        }
    }

    /**
     * 验证表达式的安全性，防止不安全的字符或代码注入
     * @param {string} expression - 需要验证的表达式
     * @returns {boolean} 返回表达式是否安全
     */
    function isSafeExpression(expression) {
        // 允许的字符集：数字、字母、运算符、括号、空白符、'arg' 引用以及允许的方法调用
        const unsafePattern = /[^0-9a-zA-Z+\-*/%<>&|^~!=.()\s,$]/;
        const forbiddenPatterns = [
            { pattern: /\b__proto__\b/, message: '__proto__ is not allowed' },
            { pattern: /\bconstructor\b/, message: 'constructor is not allowed' },
            { pattern: /\beval\b/, message: 'eval is not allowed' },
            { pattern: /\bFunction\b/, message: 'Function is not allowed' },
            { pattern: /\.([a-zA-Z_$][0-9a-zA-Z_$]*)\(/g, type: 'methodCall' } // 匹配所有方法调用
        ];

        if (unsafePattern.test(expression)) {
            return false;
        }

        for (const item of forbiddenPatterns) {
            const { pattern, type } = item;

            if (pattern.test(expression)) {
                if (type === 'methodCall') {
                    // 定义允许的方法列表
                    const allowedMethods = ['toFixed'];
                    const methodCalls = [...expression.matchAll(pattern)];
                    for (const match of methodCalls) {
                        if (!allowedMethods.includes(match[1])) {
                            return false; // 存在非允许的方法调用，判定为不安全
                        }
                    }
                } else {
                    // 存在不安全的模式，判定为不安全
                    return false;
                }
            }
        }

        return true;
    }

    // 定义 ValueType 到 Buffer 读取方法的映射
    const readMethods = {
        'Int8': 'readInt8',
        'UInt8': 'readUInt8',
        'Int16BE': 'readInt16BE',
        'Int16LE': 'readInt16LE',
        'UInt16BE': 'readUInt16BE',
        'UInt16LE': 'readUInt16LE',
        'Int32BE': 'readInt32BE',
        'Int32LE': 'readInt32LE',
        'UInt32BE': 'readUInt32BE',
        'UInt32LE': 'readUInt32LE',
        "Int64BE": 'readBigInt64BE',
        "Int64LE": 'readBigInt64LE',
        "UInt64BE": 'readBigUInt64BE',
        "UInt64LE": 'readBigUInt64LE',
        'FloatBE': 'readFloatBE',
        'FloatLE': 'readFloatLE',
        'DoubleBE': 'readDoubleBE',
        'DoubleLE': 'readDoubleLE',
        'String': 'toString',
        'Buffer': 'subarray',
        'Int48BE': 'readIntBE',
        'Int48LE': 'readIntLE',
        'UInt48BE': 'readUIntBE',
        'UInt48LE': 'readUIntLE'
    };

    const convertMethods = new Set(['String', 'Buffer', 'Int48BE', 'Int48LE', 'UInt48BE', 'UInt48LE']);

    // 转换并处理数据
    function handleData(data, columns) {
        // 将输入的Buffer数据转换为一个Buffer对象
        let buf = Buffer.from(data.buffer);
        let rtn = {}

        // 遍历每列配置
        for (const col of columns) {
            if (!col.Key || col.Offset === null) {
                console.warn(`测点配置错误：${JSON.stringify(col)}`);
                continue;
            }
            let method = readMethods[col.ValueType];
            if (method) {
                // 根据列配置的类型、偏移量读取对应数据
                try {
                    if (convertMethods.has(col.ValueType)) {
                        let value;
                        if (col.ValueType === 'String') {
                            value = buf[method]('utf8', col.Offset, col.Offset + col.Length);
                        } else if (col.ValueType === 'Buffer') {
                            value = buf[method](col.Offset, col.Offset + col.Length);
                        } {
                            value = buf[method](col.Offset, col.Length);
                        }
                    } else {
                        value = buf[method](col.Offset);
                    }
                    //rtn[col.Key + "_raw"] = value;
                    if (col.Arithmetic && ArithmeticCache[col.Arithmetic]) {
                        value = ArithmeticCache[col.Arithmetic](value);
                    }
                    rtn[col.Key] = value
                } catch (err) {
                    console.error(`Error reading buffer with method ${method} at offset ${col.Offset}`, err);
                    rtn[col.Key] = null; // 设置一个默认值或者处理错误
                }
            } else {
                console.warn(`Unsupported ValueType: ${col.ValueType}`);
                rtn[col.Key] = null; // 未知类型返回 null 或其他默认值
            }
        };
        return rtn;
    }

    // 注册一个节点 ,注册的节点不能重复
    RED.nodes.registerType("modbus-decode", Decode);
}