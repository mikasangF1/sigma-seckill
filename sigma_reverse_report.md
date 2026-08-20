# Sigma 2.17 (Bludger) 逆向分析报告

## 签署算法分析结果

### 体系结构

```
Sigma 签名体系 = NSig 层 (Native) + HMAC 层 (Native) + JWT 层 (mua) + Shield 层
```

### 五层 Header 分析

| Header | 长度 | 格式 | 变化规律 | 生成位置 |
|--------|------|------|----------|----------|
| x-mini-sig | 64 hex | SHA256-like | 每请求唯一，绑定 path+body+t+counter | Native C++ `EdithSignHeaderEPKcS1_PKhm` |
| x-mini-nsig | 64 hex | SHA256-like | 同 sig 但不同输入 | Native C++ |
| x-mini-s1 | Base64 | 计数器+随机数据 | 每请求递增 | Native |
| x-mini-mua | JWT(2段) | payload.签名 | payload 每请求变化(c计数器+新m时间戳) | Native SDK v2.2.31 |
| shield | Base64(100B) | 二进制 | 每请求不同 | XYSSHandle |

### mua JWT 结构

**Payload** (解码后):
```json
{
  "a": "4BFEF600",           // appId
  "c": 141,                  // 计数器(递增)
  "i": 2,                    // 版本
  "k": "9aeb5912...",        // 256-bit HMAC key(64 hex)
  "m": "1787150831638",      // 毫秒时间戳
  "n": "0ef75ae2...",        // 128-bit nonce(32 hex)
  "o": "ZAcw76m2...",        // 设备标识
  "p": "i",                  // 平台
  "s": "408b90ca...",        // 128-bit salt(32 hex)
  "u": "00000000...",        // 用户ID
  "v": "2.2.31"              // sdk版本
}
```

**签名段**: 464 bytes (RSA-PSS / ECDSA 签名，不能被纯静态还原)

### 签名算法不能纯静态还原的原因

1. **mua key 来自 register API 加密响应** → 需要运行时解密
2. **HMAC key 动态变化** → mua 中 k 字段每 session 不同
3. **464字节签名** → 非对称加密，需要私钥
4. **shield 100字节二进制** → 含计数器+随机数
5. **Native 代码符号 strip** → 无法定位具体函数
6. **ObjC method 表用 arm64e 相对寻址** → 解析困难
7. **114MB __text 无符号表** → 暴力扫描 1.4 亿指令不可行

### 替代方案: 凭据复用策略

**结论**: 不需要离线还原签名算法。现有方案（凭据复用）可以工作：
- x-mini-mua 和 shield 作为静态凭据从抓包获取
- x-mini-sig/x-mini-nsig 虽不发送但服务端可能不校验
- 如果在 pre_redeem 需要，从注册机获取新 mua

### 关键发现

1. kcal 页面是 RN Hermes (snitch-rn 3.23.0, 8.3MB HBC)
2. pre_redeem 请求 body: `{"activityId":1001,"productId":2002,"requestId":"kcal_ts_rand"}`
3. requestId 格式: `kcal_{13位时间戳}_{8位随机}`
4. 同 t 的不同请求 sig 全部不同 → 绑定 counter (mua.c)
5. mua.c 每请求递增 ~40-60