import os
import time
import subprocess
import psutil
import logging
import win32clipboard
import json
import winsound
import colorama
import threading
import uuid
from datetime import datetime
from colorama import Fore, Back, Style

# 初始化colorama
colorama.init(autoreset=True)

# 自定义日志格式处理器，添加颜色
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE
    }
    
    INSTANCE_COLORS = {
        # 将为不同实例分配不同的颜色
        # 这些会在运行时动态分配
    }
    
    RESET = Style.RESET_ALL
    
    def __init__(self, fmt):
        super().__init__(fmt)
        self.instance_color_index = 0
        self.available_colors = [
            Fore.BLUE, Fore.MAGENTA, Fore.CYAN, 
            Fore.GREEN, Fore.YELLOW, Fore.RED,
            Fore.LIGHTBLUE_EX, Fore.LIGHTMAGENTA_EX, Fore.LIGHTCYAN_EX,
            Fore.LIGHTGREEN_EX, Fore.LIGHTYELLOW_EX, Fore.LIGHTRED_EX
        ]
    
    def get_instance_color(self, instance_name):
        if instance_name not in self.INSTANCE_COLORS:
            color = self.available_colors[self.instance_color_index % len(self.available_colors)]
            self.INSTANCE_COLORS[instance_name] = color
            self.instance_color_index += 1
        return self.INSTANCE_COLORS[instance_name]
    
    def format(self, record):
        # 标准格式化
        log_message = super().format(record)
        
        # 为不同日志级别添加颜色
        level_color = self.COLORS.get(record.levelname, Fore.WHITE)
        
        # 查找并为实例名称添加颜色
        if hasattr(record, 'message') and '[' in record.message and ']' in record.message:
            # 提取实例名称
            start = record.message.find('[') + 1
            end = record.message.find(']')
            if start > 0 and end > start:
                instance_name = record.message[start:end]
                instance_color = self.get_instance_color(instance_name)
                
                # 替换实例名称部分为彩色版本
                colored_instance = f"{instance_color}[{instance_name}]{self.RESET}"
                log_message = log_message.replace(f"[{instance_name}]", colored_instance)
        
        # 添加级别颜色
        timestamp_end = log_message.find(' - ') + 3
        if timestamp_end > 3:
            level_start = timestamp_end
            level_end = log_message.find(' - ', timestamp_end) + 3 if ' - ' in log_message[timestamp_end:] else len(log_message)
            
            if level_end > level_start:
                level_part = log_message[level_start:level_end]
                colored_level = f"{level_color}{level_part}{self.RESET}"
                log_message = log_message[:level_start] + colored_level + log_message[level_end:]
        
        return log_message

# 配置日志 - 同时输出到文件和控制台
logger = logging.getLogger('process_guardian')
logger.setLevel(logging.INFO)

# 文件处理器 - 纯文本，不含颜色代码
file_handler = logging.FileHandler('process_guardian.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# 控制台处理器 - 带颜色
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)

# 创建全局锁，用于同步进程管理
process_management_lock = threading.RLock()

class SandboxProcess:
    """表示沙盒中运行的进程"""
    def __init__(self, pid, sandbox_name, creation_time, guardian_id):
        self.pid = pid  # 进程ID
        self.sandbox_name = sandbox_name  # 沙盒名称
        self.creation_time = creation_time  # 进程创建时间
        self.last_check_time = time.time()  # 上次检查时间
        self.guardian_id = guardian_id  # 管理此进程的守护进程ID
        self.check_count = 0  # 检查计数（用于调试）
        self.instance_id = str(uuid.uuid4())[:8]  # 进程实例的唯一标识符
    
    def __str__(self):
        return f"PID:{self.pid} [沙盒:{self.sandbox_name}] [创建时间:{datetime.fromtimestamp(self.creation_time).strftime('%H:%M:%S')}]"
        

class ProcessRegistry:
    """全局进程注册表，用于跟踪所有沙盒进程"""
    _processes = {}  # pid -> SandboxProcess
    
    @classmethod
    def register_process(cls, pid, sandbox_name, creation_time, guardian_id):
        """注册一个进程"""
        with process_management_lock:
            if pid in cls._processes:
                # 如果PID已经注册但属于不同实例，检查是否为新进程
                if cls._processes[pid].guardian_id != guardian_id:
                    try:
                        proc = psutil.Process(pid)
                        if abs(proc.create_time() - creation_time) < 1.0:  # 创建时间接近
                            # 这可能是同一个进程被不同实例检测到
                            logger.warning(f"PID {pid} 已被其他实例管理，但创建时间接近 - 保留原管理者")
                            return None
                        else:
                            # 这可能是PID重用，允许新的管理者接管
                            logger.warning(f"PID {pid} 已被其他实例管理，但创建时间不同 - 允许接管")
                            proc = SandboxProcess(pid, sandbox_name, creation_time, guardian_id)
                            cls._processes[pid] = proc
                            return proc
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        # 进程已不存在，可以重新注册
                        proc = SandboxProcess(pid, sandbox_name, creation_time, guardian_id)
                        cls._processes[pid] = proc
                        return proc
                else:
                    # 同一个实例再次注册相同的进程，返回现有记录
                    return cls._processes[pid]
            else:
                # 新进程注册
                proc = SandboxProcess(pid, sandbox_name, creation_time, guardian_id)
                cls._processes[pid] = proc
                return proc
    
    @classmethod
    def unregister_process(cls, pid, guardian_id):
        """注销一个进程"""
        with process_management_lock:
            if pid in cls._processes and cls._processes[pid].guardian_id == guardian_id:
                logger.debug(f"从注册表中移除 PID {pid}")
                del cls._processes[pid]
                return True
            return False
    
    @classmethod
    def is_process_managed(cls, pid, guardian_id):
        """检查进程是否被管理，以及是否被指定的守护进程管理"""
        with process_management_lock:
            if pid in cls._processes:
                return cls._processes[pid].guardian_id == guardian_id
            return False
    
    @classmethod
    def is_managed_by_others(cls, pid, guardian_id):
        """检查进程是否被其他守护进程管理"""
        with process_management_lock:
            if pid in cls._processes:
                return cls._processes[pid].guardian_id != guardian_id
            return False
    
    @classmethod
    def clean_dead_processes(cls):
        """清理已不存在的进程记录"""
        with process_management_lock:
            pids_to_remove = []
            for pid in cls._processes:
                try:
                    proc = psutil.Process(pid)
                    if not proc.is_running():
                        pids_to_remove.append(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pids_to_remove.append(pid)
            
            for pid in pids_to_remove:
                sandbox_name = cls._processes[pid].sandbox_name if pid in cls._processes else "未知"
                logger.debug(f"清理已终止的进程 PID:{pid} [沙盒:{sandbox_name}]")
                if pid in cls._processes:
                    del cls._processes[pid]
            
            return len(pids_to_remove)


class ProcessGuardian:
    """进程守护类，监控特定进程并在其终止时重新启动"""
    
    def __init__(self, 
                 target_process_name, 
                 target_path, 
                 sandboxie_path,
                 sandbox_name="DefaultBox",
                 clipboard_text="",
                 check_interval=5,
                 enable_sound_alert=True,
                 instance_name="未命名"):
        """
        初始化进程守护实例
        
        参数:
        target_process_name: 要监控的进程名称
        target_path: 目标软件的完整路径
        sandboxie_path: Sandboxie程序的完整路径
        sandbox_name: 沙盒名称，默认为DefaultBox
        clipboard_text: 需要复制到剪贴板的文本
        check_interval: 检查进程间隔时间（秒）
        enable_sound_alert: 是否启用声音提醒
        instance_name: 实例名称，用于日志标识
        """
        self.target_process_name = target_process_name
        self.target_path = target_path
        self.sandboxie_path = sandboxie_path
        self.sandbox_name = sandbox_name
        self.clipboard_text = clipboard_text
        self.check_interval = check_interval
        self.enable_sound_alert = enable_sound_alert
        self.running = True
        self.instance_name = instance_name
        
        # 唯一标识这个守护实例
        self.guardian_id = id(self)
        
        # 当前管理的进程
        self.managed_process = None
        
        # 运行统计
        self.start_count = 0
        self.last_start_time = 0
        self.last_check_time = 0
        self.consecutive_failures = 0
        
        logger.info(f"[{self.instance_name}] 进程守护已启动，监控进程: {target_process_name}")
    
    def copy_text_to_clipboard(self, text):
        """将文本复制到剪贴板"""
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardText(text, win32clipboard.CF_UNICODETEXT)
            win32clipboard.CloseClipboard()
            logger.info(f"[{self.instance_name}] 文本已成功复制到剪贴板")
            return True
        except Exception as e:
            logger.error(f"[{self.instance_name}] 复制文本到剪贴板失败: {str(e)}")
            return False
    
    def play_sound_alert(self):
        """播放提示音"""
        if self.enable_sound_alert:
            try:
                # 播放两次蜂鸣声，频率为1000Hz，持续时间为200毫秒
                winsound.Beep(1000, 200)
                time.sleep(0.2)
                winsound.Beep(1000, 200)
                logger.info(f"[{self.instance_name}] 已播放提示音")
            except Exception as e:
                logger.error(f"[{self.instance_name}] 播放提示音失败: {str(e)}")
    
    def find_process_by_sandbox(self, sandbox_name, recent_only=True, max_age=30):
        """
        查找在特定沙盒中运行的目标进程
        
        参数:
        sandbox_name: 沙盒名称
        recent_only: 是否只查找最近创建的进程
        max_age: 如果recent_only为True，只查找max_age秒内创建的进程
        
        返回:
        找到的进程信息列表，每个元素是字典：{pid, cmdline, create_time, match_score}
        """
        current_time = time.time()
        result = []
        
        # 获取所有可能的目标进程
        for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline']):
            try:
                # 匹配进程名
                if self.target_process_name.lower() in proc.info['name'].lower():
                    pid = proc.info['pid']
                    creation_time = proc.info['create_time']
                    
                    # 如果只查找最近创建的进程
                    if recent_only and (current_time - creation_time) > max_age:
                        continue
                    
                    # 尝试检查此进程是否在目标沙盒中运行
                    cmdline = ""
                    try:
                        # 获取命令行
                        cmdline = " ".join(proc.cmdline()).lower() if proc.cmdline() else ""
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # 尝试获取环境变量和其他信息
                    env_info = ""
                    try:
                        # 尝试获取环境变量
                        env = proc.environ()
                        env_str = str(env).lower()
                        env_info = env_str
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # 尝试获取打开的文件
                    files_info = ""
                    try:
                        # 尝试获取进程打开的文件
                        files = proc.open_files()
                        files_str = str(files).lower()
                        files_info = files_str
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # 获取父进程信息
                    parent_info = ""
                    try:
                        parent = proc.parent()
                        if parent:
                            parent_info = f"{parent.name().lower()} {' '.join(parent.cmdline()).lower()}"
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # 检查沙盒标识符，计算匹配分数
                    match_score = 0
                    sandbox_id_lower = sandbox_name.lower()
                    
                    # 进程列表中获取完整信息用于打分
                    all_info = f"{cmdline} {env_info} {files_info} {parent_info}".lower()
                    
                    # 多种匹配方式并计分
                    # 1. 完全匹配沙盒名称（最高分）
                    if f"\\{sandbox_id_lower}\\" in all_info.replace("/", "\\"):
                        match_score += 10
                    
                    # 2. 匹配沙盒名称作为独立单词
                    if f" {sandbox_id_lower} " in f" {all_info} ":
                        match_score += 8
                    
                    # 3. 匹配box:沙盒名称格式
                    if f"box:{sandbox_id_lower}" in all_info:
                        match_score += 10
                    
                    # 4. 简单包含沙盒名称
                    if sandbox_id_lower in all_info:
                        match_score += 5
                        
                    # 5. 检查路径中是否包含沙盒名称
                    if f"/box/{sandbox_id_lower}/" in all_info.replace("\\", "/"):
                        match_score += 10
                    
                    # 6. Sandboxie特有的格式
                    if f"sandboxie_{sandbox_id_lower}" in all_info:
                        match_score += 10
                    
                    # 只有有一定匹配度的进程才添加到结果中
                    if match_score > 0:
                        # 记录匹配细节，用于调试
                        match_details = []
                        if f"\\{sandbox_id_lower}\\" in all_info.replace("/", "\\"): 
                            match_details.append("路径匹配")
                        if f" {sandbox_id_lower} " in f" {all_info} ":
                            match_details.append("独立单词匹配")
                        if f"box:{sandbox_id_lower}" in all_info:
                            match_details.append("box:前缀匹配")
                        
                        logger.debug(f"[{self.instance_name}] 找到可能的匹配进程: PID={pid}, 分数={match_score}, 匹配={','.join(match_details) or '简单包含'}")
                        
                        result.append({
                            'pid': pid,
                            'cmdline': cmdline,
                            'create_time': creation_time,
                            'match_score': match_score
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # 先按匹配分数排序（高分优先），分数相同时按创建时间排序（新的优先）
        result.sort(key=lambda x: (-x['match_score'], -x['create_time']))
        return result
    
    def start_process_in_sandbox(self):
        """在沙盒中启动目标进程"""
        # 检查时间间隔，防止过于频繁的启动
        current_time = time.time()
        if current_time - self.last_start_time < 5:  # 至少5秒间隔
            logger.debug(f"[{self.instance_name}] 上次启动过于频繁，等待间隔...")
            time.sleep(5 - (current_time - self.last_start_time))
        
        self.last_start_time = time.time()
        self.start_count += 1
        
        logger.info(f"[{self.instance_name}] 使用Sandboxie的{self.sandbox_name}沙盒启动程序: {self.target_path} (第{self.start_count}次尝试)")
        
        try:
            # 在启动程序前将文本复制到剪贴板
            if self.clipboard_text:
                self.copy_text_to_clipboard(self.clipboard_text)
            
            # 获取启动前存在的进程列表及其匹配分数
            before_processes = self.find_process_by_sandbox(self.sandbox_name)
            before_pids = {p['pid']: p for p in before_processes}
            
            # 启动Sandboxie并运行目标程序
            cmd = f'"{self.sandboxie_path}" /box:{self.sandbox_name} "{self.target_path}"'
            process = subprocess.Popen(cmd, shell=True)
            
            # 记录启动时间
            start_time = time.time()
            
            # 等待新进程出现
            max_wait_time = 30  # 最多等待30秒
            new_process = None
            
            logger.info(f"[{self.instance_name}] 等待程序启动...")
            
            # 记录每次循环中的最佳候选进程，以防止找不到完美匹配时有备选
            best_candidate = None
            best_score = 0
            
            for wait_count in range(1, max_wait_time + 1):
                time.sleep(1)  # 每秒检查一次
                
                # 查找最近创建的、与目标沙盒关联的所有进程
                current_processes = self.find_process_by_sandbox(self.sandbox_name, recent_only=True, max_age=max_wait_time)
                
                # 如果没有找到任何进程，继续等待
                if not current_processes:
                    if wait_count % 5 == 0 or wait_count == 1:
                        logger.info(f"[{self.instance_name}] 等待程序启动中，未找到匹配进程，已尝试 {wait_count}/{max_wait_time} 秒...")
                    continue
                
                # 筛选出新创建的进程或匹配度更高的进程
                for proc in current_processes:
                    pid = proc['pid']
                    match_score = proc.get('match_score', 0)
                    
                    # 如果是新进程，或者匹配度比之前高
                    is_new_process = pid not in before_pids
                    is_recent_process = abs(proc['create_time'] - start_time) < wait_count + 5
                    
                    # 检查是否是合适的候选进程
                    if (is_new_process or is_recent_process):
                        # 检查此进程是否已被其他实例管理
                        if ProcessRegistry.is_managed_by_others(pid, self.guardian_id):
                            other_instance = "未知实例"
                            # 尝试查找哪个实例在管理此进程
                            for name, _, guardian in threads:
                                if guardian.managed_process and guardian.managed_process.pid == pid:
                                    other_instance = name
                                    break
                            
                            logger.warning(f"[{self.instance_name}] 检测到进程 PID={pid} 已被 {other_instance} 管理")
                            
                            # 如果匹配分数更高，可能是找到了更好的匹配，记录警告
                            if match_score > 15:  # 设置一个高阈值表示很确定的匹配
                                logger.warning(f"[{self.instance_name}] 进程 PID={pid} 与当前沙盒匹配度很高(分数={match_score})，但已被其他实例管理")
                            continue
                        
                        # 更新最佳候选进程
                        if match_score > best_score:
                            best_candidate = proc
                            best_score = match_score
                            logger.debug(f"[{self.instance_name}] 更新候选进程: PID={pid}, 匹配分数={match_score}")
                        
                        # 如果匹配分数足够高，直接选择此进程
                        if match_score >= 10:  # 阈值可调整
                            # 找到一个新进程，尝试注册
                            registered = ProcessRegistry.register_process(
                                pid, self.sandbox_name, proc['create_time'], self.guardian_id
                            )
                            
                            if registered:
                                # 注册成功，找到了我们的进程
                                new_process = {
                                    'pid': pid,
                                    'create_time': proc['create_time'],
                                    'match_score': match_score,
                                    'sandbox_process': registered
                                }
                                logger.info(f"[{self.instance_name}] 找到高匹配度进程: PID={pid}, 匹配分数={match_score}")
                                break
                
                # 如果找到了合适的进程，跳出等待循环
                if new_process:
                    break
                
                # 输出等待进度
                if wait_count % 5 == 0 or wait_count == 1:
                    if best_candidate:
                        logger.info(f"[{self.instance_name}] 等待程序启动中，当前最佳候选: PID={best_candidate['pid']}, 分数={best_score}, 已尝试 {wait_count}/{max_wait_time} 秒...")
                    else:
                        logger.info(f"[{self.instance_name}] 等待程序启动中，已尝试 {wait_count}/{max_wait_time} 秒...")
            
            # 如果等待超时但有最佳候选进程，尝试使用它
            if not new_process and best_candidate and best_score > 0:
                pid = best_candidate['pid']
                logger.warning(f"[{self.instance_name}] 等待超时，尝试使用最佳候选进程: PID={pid}, 匹配分数={best_score}")
                
                # 确认进程没有被其他实例管理
                if not ProcessRegistry.is_managed_by_others(pid, self.guardian_id):
                    registered = ProcessRegistry.register_process(
                        pid, self.sandbox_name, best_candidate['create_time'], self.guardian_id
                    )
                    
                    if registered:
                        new_process = {
                            'pid': pid,
                            'create_time': best_candidate['create_time'],
                            'match_score': best_score,
                            'sandbox_process': registered
                        }
            
            # 处理结果
            if new_process:
                # 找到新进程，更新管理状态
                self.managed_process = new_process['sandbox_process']
                match_details = f"匹配分数={new_process.get('match_score', '未知')}"
                logger.info(f"[{self.instance_name}] 程序已启动，进程ID: {self.managed_process.pid} ({match_details}) (由本程序管理)")
                
                # 重置连续失败计数
                self.consecutive_failures = 0
                
                # 播放提示音
                self.play_sound_alert()
                
                return True
            else:
                # 未找到新进程，启动失败
                logger.error(f"[{self.instance_name}] 等待程序启动超时，未能找到匹配的进程")
                self.consecutive_failures += 1
                return False
                
        except Exception as e:
            logger.error(f"[{self.instance_name}] 启动程序失败: {str(e)}")
            self.consecutive_failures += 1
            return False
    
    def is_managed_process_running(self):
        """检查当前管理的进程是否仍在运行"""
        if not self.managed_process:
            return False
        
        try:
            pid = self.managed_process.pid
            
            # 首先检查PID是否仍在注册表中
            if not ProcessRegistry.is_process_managed(pid, self.guardian_id):
                logger.warning(f"[{self.instance_name}] PID {pid} 不再由本实例管理")
                self.managed_process = None
                return False
            
            # 多次尝试检查进程状态，避免瞬时错误
            retry_count = 0
            max_retries = 3  # 最多重试3次
            
            while retry_count < max_retries:
                try:
                    # 检查进程是否存在并运行
                    proc = psutil.Process(pid)
                    
                    # 检查进程名是否匹配
                    proc_name = proc.name().lower()
                    if self.target_process_name.lower() not in proc_name:
                        # 再次尝试获取进程名，有时可能因为瞬时问题获取失败
                        retry_count += 1
                        if retry_count < max_retries:
                            time.sleep(0.2)  # 短暂延迟后重试
                            continue
                        
                        logger.warning(f"[{self.instance_name}] PID {pid} 存在但进程名不匹配 (当前: {proc_name})")
                        ProcessRegistry.unregister_process(pid, self.guardian_id)
                        self.managed_process = None
                        return False
                    
                    # 检查进程是否仍在运行且非僵尸状态
                    if not proc.is_running():
                        retry_count += 1
                        if retry_count < max_retries:
                            time.sleep(0.2)  # 短暂延迟后重试
                            continue
                        
                        logger.warning(f"[{self.instance_name}] PID {pid} 已不再运行")
                        ProcessRegistry.unregister_process(pid, self.guardian_id)
                        self.managed_process = None
                        return False
                    
                    # 检查进程状态
                    try:
                        status = proc.status()
                        if status == psutil.STATUS_ZOMBIE:
                            retry_count += 1
                            if retry_count < max_retries:
                                time.sleep(0.2)  # 短暂延迟后重试
                                continue
                            
                            logger.warning(f"[{self.instance_name}] PID {pid} 处于僵尸状态")
                            ProcessRegistry.unregister_process(pid, self.guardian_id)
                            self.managed_process = None
                            return False
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        retry_count += 1
                        if retry_count < max_retries:
                            time.sleep(0.2)  # 短暂延迟后重试
                            continue
                        
                        logger.warning(f"[{self.instance_name}] 无法获取 PID {pid} 的状态")
                        ProcessRegistry.unregister_process(pid, self.guardian_id)
                        self.managed_process = None
                        return False
                    
                    # 所有检查通过，进程正在运行
                    self.managed_process.last_check_time = time.time()
                    self.managed_process.check_count += 1
                    return True
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    retry_count += 1
                    if retry_count < max_retries:
                        time.sleep(0.2)  # 短暂延迟后重试
                        continue
                    
                    logger.warning(f"[{self.instance_name}] PID {pid} 不存在或无法访问")
                    ProcessRegistry.unregister_process(pid, self.guardian_id)
                    self.managed_process = None
                    return False
                
                # 如果执行到这里，说明当前尝试没有问题，不需要继续重试
                break
                
        except Exception as e:
            logger.error(f"[{self.instance_name}] 检查进程状态时出错: {str(e)}")
            # 出错时不立即释放进程管理权，避免因瞬时错误导致频繁重启
            # 只在连续多次错误后才释放
            if hasattr(self, '_error_count'):
                self._error_count += 1
            else:
                self._error_count = 1
            
            if self._error_count >= 3:  # 连续3次出错才释放管理权
                self.managed_process = None
                self._error_count = 0
            
            return False
    
    def start_monitoring(self):
        """开始监控进程"""
        logger.info(f"[{self.instance_name}] 开始监控进程...")
        
        # 先启动一次程序
        self.start_process_in_sandbox()
        
        # 监控循环
        process_missing_count = 0  # 进程不存在的连续检测次数
        max_missing_count = 2      # 连续检测到进程不存在几次才确认终止
        
        while self.running:
            try:
                # 记录当前检查时间
                self.last_check_time = time.time()
                
                # 检查当前管理的进程是否仍在运行
                is_running = self.is_managed_process_running()
                
                if not is_running:
                    # 进程可能已终止，但要多次确认，防止误判
                    process_missing_count += 1
                    
                    if process_missing_count >= max_missing_count:
                        # 连续多次确认进程不存在，认为进程已终止
                        logger.warning(f"[{self.instance_name}] 连续{process_missing_count}次检测到进程已终止，准备重启")
                        
                        # 重置计数
                        process_missing_count = 0
                        
                        # 根据连续失败次数调整等待时间
                        if self.consecutive_failures > 0:
                            wait_time = min(self.consecutive_failures * 3, 30)  # 最多等待30秒
                            logger.info(f"[{self.instance_name}] 已连续失败{self.consecutive_failures}次，等待{wait_time}秒后重试")
                            time.sleep(wait_time)
                        
                        # 尝试启动进程
                        success = self.start_process_in_sandbox()
                        
                        if not success:
                            self.consecutive_failures += 1
                            if self.consecutive_failures >= 5:
                                logger.error(f"[{self.instance_name}] 已连续失败{self.consecutive_failures}次，可能存在严重问题")
                        else:
                            # 重启成功，重置失败计数
                            self.consecutive_failures = 0
                    else:
                        # 第一次检测到进程不存在，先记录，不急于重启
                        logger.debug(f"[{self.instance_name}] 未检测到进程运行 ({process_missing_count}/{max_missing_count})，等待下一次确认")
                else:
                    # 进程运行正常，重置缺失计数
                    process_missing_count = 0
                    # 重置错误计数
                    if hasattr(self, '_error_count'):
                        self._error_count = 0
                    
                    # 进程正常运行时的日志级别调低，避免日志过多
                    if self.managed_process and self.managed_process.check_count % 10 == 0:  # 每10次检查输出一次日志
                        logger.debug(f"[{self.instance_name}] 由本程序管理的进程 (PID: {self.managed_process.pid}) 正在运行")
            
            except Exception as e:
                logger.error(f"[{self.instance_name}] 监控过程中发生错误: {str(e)}")
                time.sleep(1)  # 避免因错误导致的CPU过度使用
            
            # 检查间隔
            time.sleep(self.check_interval)
    
    def stop_monitoring(self):
        """停止监控"""
        self.running = False
        logger.info(f"[{self.instance_name}] 进程监控已停止")


def load_config():
    """从配置文件加载设置"""
    config_path = "config.json"
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                logger.info("成功加载配置文件")
                return config
        else:
            # 如果配置文件不存在，创建默认多实例配置
            default_config = {
                "global_settings": {
                    "check_interval": 5,
                    "enable_sound_alert": True
                },
                "instances": [
                    {
                        "name": "实例1",
                        "target_process": "捞月狗.exe",
                        "target_path": r"C:\Users\Administrator\AppData\Local\Programs\lyg\捞月狗.exe",
                        "sandboxie_path": r"D:\sandboxie\Start.exe",
                        "sandbox_name": "1",
                        "clipboard_text": "12345678"
                    }
                ]
            }
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=4, ensure_ascii=False)
                logger.info("已创建默认配置文件")
            return default_config
    except Exception as e:
        logger.error(f"加载配置文件失败: {str(e)}")
        return None


def main():
    """主函数"""
    # 从配置文件加载设置
    config = load_config()
    if not config:
        logger.error("无法加载配置，程序退出")
        return
    
    # 获取全局设置
    global_settings = config.get("global_settings", {})
    check_interval = global_settings.get("check_interval", 5)
    enable_sound_alert = global_settings.get("enable_sound_alert", True)
    
    # 启动多个实例的监控
    guardians = []
    instances = config.get("instances", [])
    
    if not instances:
        logger.warning("配置文件中未找到任何实例配置，程序退出")
        return
    
    # 创建各实例的进程守护对象
    for instance in instances:
        try:
            guardian = ProcessGuardian(
                target_process_name=instance["target_process"],
                target_path=instance["target_path"],
                sandboxie_path=instance["sandboxie_path"],
                sandbox_name=instance["sandbox_name"],
                clipboard_text=instance["clipboard_text"],
                check_interval=check_interval,
                enable_sound_alert=enable_sound_alert,
                instance_name=instance.get("name", "未命名")
            )
            guardians.append((instance.get("name", "未命名"), guardian))
            logger.info(f"已创建实例监控: {instance.get('name', '未命名')}")
        except Exception as e:
            logger.error(f"创建实例监控失败: {str(e)}")
    
    # 如果没有成功创建任何守护实例，退出程序
    if not guardians:
        logger.error("未能创建任何进程守护实例，程序退出")
        return
    
    # 创建并启动多个线程，每个线程监控一个实例
    threads = []
    
    for name, guardian in guardians:
        thread = threading.Thread(
            target=guardian.start_monitoring,
            name=f"Monitor-{name}"
        )
        thread.daemon = True  # 设置为守护线程，主线程结束时自动结束
        thread.start()
        threads.append((name, thread, guardian))
        logger.info(f"已启动监控线程: {name}")
    
    # 看门狗线程，用于监控所有线程的状态和定期清理
    def watchdog():
        while True:
            try:
                # 检查所有监控线程是否存活
                for name, thread, guardian in threads:
                    if not thread.is_alive():
                        logger.warning(f"监控线程 {name} 已停止运行，尝试重启...")
                        # 创建新线程替代已停止的线程
                        new_thread = threading.Thread(
                            target=guardian.start_monitoring,
                            name=f"Monitor-{name}-Restarted"
                        )
                        new_thread.daemon = True
                        new_thread.start()
                        
                        # 更新线程列表
                        for i, (t_name, _, _) in enumerate(threads):
                            if t_name == name:
                                threads[i] = (name, new_thread, guardian)
                                break
                                
                        logger.info(f"监控线程 {name} 已成功重启")
                
                # 清理死亡进程记录
                removed = ProcessRegistry.clean_dead_processes()
                if removed > 0:
                    logger.debug(f"已清理 {removed} 个无效的进程记录")
                
                # 输出状态摘要
                alive_processes = sum(1 for _, _, g in threads if g.managed_process is not None)
                logger.info(f"进程状态摘要: {alive_processes}/{len(threads)} 个实例正在管理活跃进程")
                
            except Exception as e:
                logger.error(f"看门狗线程发生错误: {str(e)}")
            
            # 30秒检查一次
            time.sleep(30)
    
    # 启动看门狗线程
    watchdog_thread = threading.Thread(target=watchdog, name="Watchdog")
    watchdog_thread.daemon = True
    watchdog_thread.start()
    
    try:
        # 主线程等待，接收键盘中断
        while True:
            time.sleep(1)
            alive_threads = [t for _, t, _ in threads if t.is_alive()]
            if not alive_threads:
                logger.warning("所有监控线程已结束，程序退出")
                break
    except KeyboardInterrupt:
        # 停止所有监控
        for name, _, guardian in threads:
            guardian.stop_monitoring()
            logger.info(f"已停止实例监控: {name}")
        logger.info("程序已通过键盘中断退出")
        print("\n程序已通过键盘中断退出")


if __name__ == "__main__":
    main()