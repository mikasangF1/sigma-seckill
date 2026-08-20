# Sigma 2.17 (Bludger) 逆向分析最终报告

## 逆向结果

### 签名体系：不可纯静态还原 ❌

| 组件 | 能否还原 | 原因 |
|------|---------|------|
| x-mini-sig (64 hex) | ❌ | 绑定 body+path+time+counter，key 来自 mua 运行时生成 |
| x-mini-nsig (64 hex) | ❌ | 同上，不同输入 |
| x-mini-s1 (62B Base64) | ❌ | 含随机数，不可预测 |
| x-mini-mua (JWT 2段) | ❌ | 签名段 464 字节，需 RSA 私钥 |
| shield (100B Base64) | ❌ | 前84B静态，后16B随机数 |

### 不可还原的根因

1. **mua 签名段 464 字节** → 非对称加密（RSA-PSS），需要私钥，不在二进制中
2. **mua.key 每 session 不同** → 来自 register API 加密响应，需运行时解密
3. **shield 后 16 字节** → 随机数，不可预测
4. **sig 绑定 mua.counter** → 不用注册机无法维持计数器同步
5. **Native 代码符号 stripped** → 114MB __text 无符号表，无法定位关键函数
6. **arm64e 指针认证** → ObjC method list 用相对寻址，遍历困难

### 现有脚本方案评估

现有 `sigma_seckill.js` 使用静态 mua/shield 从抓包获取，**未发送 sig/nsig/s1**。根据 HAR 分析，sig/nsig/mua/shield 总是同时出现（251 请求全带），服务端很可能校验这些字段。

**~需加注册机~** 通过 iOS 真机/抓包定期刷新 mua 和 shield。

### 更新脚本

仍然更新了脚本：
1. 基于 HAR 分析修正了 app_id 和 project_id 规则
2. 添加了 `getCommonParams` 的路由判断
3. 添加了 `getHome` 查询余额/库存功能
4. 更新了 schedule 规则
5. 添加了注册机接口（通过 register/ios 获取新 mua 和 shield）
6. 添加了重试 + 防假成功逻辑

### 后续建议

如果服务端强制校验 sig，需要：
1. 越狱 iPhone 上用 Frida hook `EdithSignHeaderEPKcS1_PKhm` 获取运行时输入输出
2. 或者用注册机方案：模拟 register/ios → cfg/ios → 获取有效 mua/shield