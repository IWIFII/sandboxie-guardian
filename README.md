# Sandboxie进程守护与启动工具

## 项目简介

Sandboxie进程守护工具是一个专注于进程监控与自动化沙盒启动的实用工具。它能够持续监控指定程序的运行状态，在进程异常退出时自动重启，并利用 Sandboxie 技术在隔离的沙盒环境中启动多个应用程序实例，实现多开和安全隔离。

## 功能特点

- 支持多个沙盒实例的配置和管理
- 定期检查进程状态
- 声音提醒功能
- 自动设置剪贴板文本
- 简单易用的配置方式

## 配置说明

配置文件 `config.json` 包含以下设置：

### 全局设置

```json
"global_settings": {
    "check_interval": 5,        // 检查间隔时间（秒）
    "enable_sound_alert": true  // 启用声音提醒
}
```

### 实例配置

每个实例可以配置以下参数：

| 参数 | 描述 |
|------|------|
| name | 实例名称 |
| target_process | 目标进程名称 |
| target_path | 目标程序路径 |
| sandboxie_path | Sandboxie 启动程序路径 |
| sandbox_name | 沙盒名称 |
| clipboard_text | 自动设置到剪贴板的文本 |

## 使用方法

1. 确保已安装 Sandboxie 并正确配置
2. 根据需要修改 `config.json` 文件
3. 运行程序启动管理工具
4. 程序将根据配置自动在指定的沙盒中启动目标应用

## 示例配置

```json
{
    "global_settings": {
        "check_interval": 5,
        "enable_sound_alert": true
    },
    "instances": [
        {
            "name": "实例1",
            "target_process": "捞月狗.exe",
            "target_path": "C:\\Users\\Administrator\\AppData\\Local\\Programs\\lyg\\捞月狗.exe",
            "sandboxie_path": "D:\\sandboxie\\Start.exe",
            "sandbox_name": "1",
            "clipboard_text": "12345678"
        },
        {
            "name": "实例2",
            "target_process": "捞月狗.exe",
            "target_path": "C:\\Users\\Administrator\\AppData\\Local\\Programs\\lyg\\捞月狗.exe",
            "sandboxie_path": "D:\\sandboxie\\Start.exe",
            "sandbox_name": "2",
            "clipboard_text": "87654321"
        }
    ]
}
```

## 注意事项

- 确保路径设置正确，包括目标程序和 Sandboxie 的路径
- 每个沙盒实例需要使用不同的沙盒名称
- 如需添加更多实例，请按照现有格式在 `instances` 数组中添加新的配置项
