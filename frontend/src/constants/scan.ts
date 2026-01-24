/**
 * 扫描相关常量配置
 * 统一管理漏洞类型、扫描步骤、状态颜色等配置
 */

// ============ 漏洞类型配置 ============
export interface VulnTypeConfig {
  value: string
  label: string
  colorClass: string
  description?: string
  cwe?: string[]
}

/**
 * 支持的漏洞类型列表
 * 按危险程度排序
 */
export const VULN_TYPES: VulnTypeConfig[] = [
  { value: 'rce', label: 'RCE', colorClass: 'bg-red-500', description: '远程代码执行', cwe: ['CWE-94'] },
  { value: 'command_injection', label: '命令注入', colorClass: 'bg-red-400', description: '操作系统命令注入', cwe: ['CWE-78'] },
  { value: 'sql_injection', label: 'SQL 注入', colorClass: 'bg-orange-500', description: 'SQL 语句注入', cwe: ['CWE-89'] },
  { value: 'file_read', label: '文件读取', colorClass: 'bg-orange-400', description: '任意文件读取', cwe: ['CWE-22'] },
  { value: 'file_write', label: '文件写入', colorClass: 'bg-orange-400', description: '任意文件写入', cwe: ['CWE-22'] },
  { value: 'ssrf', label: 'SSRF', colorClass: 'bg-yellow-500', description: '服务端请求伪造', cwe: ['CWE-918'] },
  { value: 'ssti', label: 'SSTI', colorClass: 'bg-purple-500', description: '服务端模板注入', cwe: ['CWE-94'] },
  { value: 'deserialization', label: '反序列化', colorClass: 'bg-purple-400', description: '不安全的反序列化', cwe: ['CWE-502'] },
  { value: 'auth_bypass', label: '认证绕过', colorClass: 'bg-pink-500', description: '身份验证绕过', cwe: ['CWE-287'] },
  { value: 'idor', label: 'IDOR', colorClass: 'bg-pink-400', description: '不安全的直接对象引用', cwe: ['CWE-639'] },
  { value: 'logic_flaw', label: '逻辑漏洞', colorClass: 'bg-indigo-500', description: '业务逻辑缺陷', cwe: ['CWE-840'] },
]

/**
 * 默认选中的漏洞类型
 */
export const DEFAULT_VULN_TYPES = ['rce', 'command_injection', 'sql_injection']

// ============ 扫描步骤配置 ============
export interface ScanStepConfig {
  key: string
  label: string
  icon?: string
}

/**
 * 扫描步骤定义
 */
export const SCAN_STEPS: ScanStepConfig[] = [
  { key: 'indexing', label: '索引' },
  { key: 'analyzing', label: '分析' },
  { key: 'detecting', label: '检测' },
  { key: 'completed', label: '完成' },
]

// ============ 状态颜色配置 ============
export const STATUS_COLORS: Record<string, string> = {
  completed: 'bg-green-500',
  analyzing: 'bg-blue-500',
  indexing: 'bg-yellow-500',
  detecting: 'bg-purple-500',
  pending: 'bg-gray-400',
  failed: 'bg-red-500',
  running: 'bg-blue-500',
  idle: 'bg-gray-400',
}

/**
 * 获取状态对应的颜色类
 */
export function getStatusColor(status: string): string {
  return STATUS_COLORS[status] || 'bg-gray-400'
}

// ============ 严重性配置 ============
export interface SeverityConfig {
  value: string
  label: string
  colorClass: string
  textClass: string
  bgClass: string
  borderClass: string
}

export const SEVERITY_CONFIGS: Record<string, SeverityConfig> = {
  critical: {
    value: 'critical',
    label: '严重',
    colorClass: 'text-red-600',
    textClass: 'text-red-600',
    bgClass: 'bg-red-50',
    borderClass: 'border-red-200',
  },
  high: {
    value: 'high',
    label: '高危',
    colorClass: 'text-orange-600',
    textClass: 'text-orange-600',
    bgClass: 'bg-orange-50',
    borderClass: 'border-orange-200',
  },
  medium: {
    value: 'medium',
    label: '中危',
    colorClass: 'text-yellow-600',
    textClass: 'text-yellow-600',
    bgClass: 'bg-yellow-50',
    borderClass: 'border-yellow-200',
  },
  low: {
    value: 'low',
    label: '低危',
    colorClass: 'text-blue-600',
    textClass: 'text-blue-600',
    bgClass: 'bg-blue-50',
    borderClass: 'border-blue-200',
  },
  info: {
    value: 'info',
    label: '信息',
    colorClass: 'text-gray-600',
    textClass: 'text-gray-600',
    bgClass: 'bg-gray-50',
    borderClass: 'border-gray-200',
  },
}

/**
 * 获取严重性配置
 */
export function getSeverityConfig(severity: string): SeverityConfig {
  return SEVERITY_CONFIGS[severity] || SEVERITY_CONFIGS.info
}

// ============ 默认扫描配置 ============
export const DEFAULT_SCAN_CONFIG = {
  languages: [] as string[],
  vulnTypes: DEFAULT_VULN_TYPES,
  useLLM: true,
  scanLogic: true,
  useChainAnalysis: true,
  reindex: false,
  skipIndex: false,
  maxIssues: 50,
  maxChainDepth: 5,
  enableTriage: true,
  enableDeepVerify: true,
  enableDeterministicValidation: true,
}

// ============ 限制常量 ============
export const LIMITS = {
  MAX_LOG_ENTRIES: 100,
  MAX_FINDINGS: 100,
  MAX_CHAT_MESSAGES: 500,
  MAX_TOOL_CALLS: 200,
  WEBSOCKET_RECONNECT_DELAY: 3000,
  WEBSOCKET_MAX_RETRIES: 5,
  POLL_INTERVAL: 2000,
}

// ============ 状态文本映射 ============
export const STATUS_TEXT: Record<string, string> = {
  completed: '扫描完成',
  analyzing: '分析中',
  indexing: '索引中',
  detecting: '漏洞检测中',
  pending: '准备中',
  failed: '扫描失败',
  ready: '就绪',
  processing: '处理中',
  idle: '空闲',
  error: '错误',
}

/**
 * 获取状态文本
 */
export function getStatusText(status: string): string {
  return STATUS_TEXT[status] || status
}

// ============ 状态徽章样式 ============
export const STATUS_BADGE_CLASSES: Record<string, string> = {
  completed: 'bg-green-100 text-green-700',
  analyzing: 'bg-blue-100 text-blue-700',
  indexing: 'bg-yellow-100 text-yellow-700',
  detecting: 'bg-purple-100 text-purple-700',
  pending: 'bg-gray-100 text-gray-600',
  failed: 'bg-red-100 text-red-700',
  ready: 'bg-green-500/20 text-green-300',
  processing: 'bg-blue-500/20 text-blue-300',
  idle: 'bg-gray-500/20 text-gray-300',
  error: 'bg-red-500/20 text-red-300',
}

/**
 * 获取状态徽章样式类
 */
export function getStatusBadgeClass(status: string): string {
  return STATUS_BADGE_CLASSES[status] || 'bg-gray-100 text-gray-600'
}

// ============ 进度条颜色 ============
export const PROGRESS_COLORS: Record<string, string> = {
  completed: '#34C759',
  analyzing: '#007AFF',
  indexing: '#FF9500',
  detecting: '#AF52DE',
  pending: '#8E8E93',
  failed: '#FF3B30',
}

/**
 * 获取进度条颜色
 */
export function getProgressColor(status: string): string {
  return PROGRESS_COLORS[status] || '#8E8E93'
}
