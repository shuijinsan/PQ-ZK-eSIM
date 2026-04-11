# PQ-ZK-eSIM Android 终端集成模块
本模块为项目提供 Android 端 eSIM 身份认证演示，全程不修改算法/后端任何代码，仅做上层集成与可视化。

## 你能看到什么
- 抗量子零知识认证流程可视化
- eUICC 安全存储模拟
- TEE/StrongBox 硬件安全演示
- JNI 与底层算法库无缝对接
- 一键运行完整认证流程

## 运行环境
- Android Studio Jellyfish+
- NDK r26d
- minSdkVersion 28 (Android 9.0)
- targetSdkVersion 34

## 核心功能
1. 设备初始化与密钥安全写入
2. 内外承诺生成与聚合
3. 挑战获取与生物特征授权
4. 掩码计算与计数器原子更新
5. 结果聚合与服务端验证

## 目录说明
- app/：Android 界面与业务逻辑
- cpp/：JNI 桥接代码
- jniLibs/：预编译算法库
- docs/：使用文档与规范
- scripts/：一键编译/安装脚本

## 安全规范（严格遵守）
- Java 层不做任何敏感计算
- AuthToken 仅透传不验证
- 计数器与密钥原子更新
- 所有多项式按小端序传输

本模块为项目完整闭环提供终端侧支撑，可直接编译运行。
