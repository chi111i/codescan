/**
 * 统一语言配置
 * 所有前端组件使用此配置以确保一致性
 */

export interface LanguageConfig {
  value: string
  label: string
  icon: string
  iconClass: string
  extensions?: string[]
}

/**
 * 支持的编程语言列表（15种）
 * 按使用频率和安全审计重要性排序
 * 使用渐变色和阴影效果提升视觉效果
 */
export const AVAILABLE_LANGUAGES: LanguageConfig[] = [
  // 核心语言（高优先级）
  { value: 'python', label: 'Python', icon: 'Py', iconClass: 'lang-icon-python', extensions: ['.py'] },
  { value: 'javascript', label: 'JavaScript', icon: 'JS', iconClass: 'lang-icon-javascript', extensions: ['.js', '.jsx', '.mjs'] },
  { value: 'typescript', label: 'TypeScript', icon: 'TS', iconClass: 'lang-icon-typescript', extensions: ['.ts', '.tsx'] },
  { value: 'php', label: 'PHP', icon: 'PHP', iconClass: 'lang-icon-php', extensions: ['.php'] },
  { value: 'java', label: 'Java', icon: 'JV', iconClass: 'lang-icon-java', extensions: ['.java'] },
  { value: 'go', label: 'Go', icon: 'Go', iconClass: 'lang-icon-go', extensions: ['.go'] },
  { value: 'ruby', label: 'Ruby', icon: 'Rb', iconClass: 'lang-icon-ruby', extensions: ['.rb', '.erb'] },

  // 系统语言
  { value: 'c', label: 'C', icon: 'C', iconClass: 'lang-icon-c', extensions: ['.c', '.h'] },
  { value: 'cpp', label: 'C++', icon: 'C++', iconClass: 'lang-icon-cpp', extensions: ['.cpp', '.hpp', '.cc', '.cxx'] },
  { value: 'csharp', label: 'C#', icon: 'C#', iconClass: 'lang-icon-csharp', extensions: ['.cs'] },
  { value: 'rust', label: 'Rust', icon: 'Rs', iconClass: 'lang-icon-rust', extensions: ['.rs'] },

  // JVM 语言
  { value: 'kotlin', label: 'Kotlin', icon: 'Kt', iconClass: 'lang-icon-kotlin', extensions: ['.kt', '.kts'] },
  { value: 'scala', label: 'Scala', icon: 'Sc', iconClass: 'lang-icon-scala', extensions: ['.scala', '.sc'] },

  // 其他
  { value: 'swift', label: 'Swift', icon: 'Sw', iconClass: 'lang-icon-swift', extensions: ['.swift'] },
  { value: 'dart', label: 'Dart', icon: 'Dt', iconClass: 'lang-icon-dart', extensions: ['.dart'] },
]

/**
 * 语言值列表（用于验证）
 */
export const SUPPORTED_LANGUAGE_VALUES = AVAILABLE_LANGUAGES.map(lang => lang.value)

/**
 * 根据语言值获取配置
 */
export function getLanguageConfig(value: string): LanguageConfig | undefined {
  return AVAILABLE_LANGUAGES.find(lang => lang.value === value)
}

/**
 * 根据文件扩展名获取语言
 */
export function getLanguageByExtension(filename: string): LanguageConfig | undefined {
  const ext = filename.substring(filename.lastIndexOf('.'))
  return AVAILABLE_LANGUAGES.find(lang => lang.extensions?.includes(ext))
}

export default AVAILABLE_LANGUAGES
