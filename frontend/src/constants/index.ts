/**
 * 常量统一导出
 * 所有业务常量从这里导入
 */

// 语言配置
export {
  AVAILABLE_LANGUAGES,
  SUPPORTED_LANGUAGE_VALUES,
  getLanguageConfig,
  getLanguageByExtension,
  type LanguageConfig,
} from './languages'

// 扫描配置
export {
  VULN_TYPES,
  DEFAULT_VULN_TYPES,
  SCAN_STEPS,
  STATUS_COLORS,
  SEVERITY_CONFIGS,
  DEFAULT_SCAN_CONFIG,
  LIMITS,
  STATUS_TEXT,
  STATUS_BADGE_CLASSES,
  PROGRESS_COLORS,
  getStatusColor,
  getSeverityConfig,
  getStatusText,
  getStatusBadgeClass,
  getProgressColor,
  type VulnTypeConfig,
  type ScanStepConfig,
  type SeverityConfig,
} from './scan'
