# LPA 前端（Android）

LPA（Local Profile Assistant）前端是 Android App（Kotlin + native JNI）。

## 启动方式

这是 Android 工程，需 Android Studio + SDK/NDK 编译运行。

## ⚠️ 重要说明

**reviewer 复现论文实验不依赖此前端** —— 论文实验在 Linux/QEMU 的 C 代码（euicc/）上运行。
本目录仅作参考/完整系统前端，不参与 claims 复现。

端到端 demo 的 LPA 部分由 `euicc` 的 `pqzkesim_app` 在进程内模拟（见 `artifact/demo/run.sh`），
**不启动本 Android 前端**。

## 结构

```
lpa/
├── app/      Android 工程（Kotlin 前端 + native JNI）
├── opencv/   人脸检测依赖
├── gradle/ + settings.gradle.kts + gradlew  构建配置
```
