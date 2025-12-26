import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 300000, // 5 分钟超时，支持复杂 LLM 分析
})

// 响应拦截器（含自动重试）
api.interceptors.response.use(
  (response) => response.data,
  async (error) => {
    const config = error.config

    // 简单的重试策略：针对超时或 5xx 错误重试一次
    if (config && !config.__isRetry && (error.code === 'ECONNABORTED' || (error.response && error.response.status >= 500))) {
      config.__isRetry = true
      console.warn(`Request failed, retrying: ${config.url}`)
      return api(config)
    }

    console.error('API Error:', error)
    return Promise.reject(error)
  }
)

// 健康检查
export const checkHealth = () => api.get('/health')

// 索引相关
export const indexProject = (data) => api.post('/index', data)
export const getIndexStats = () => api.get('/index/stats')

// 搜索相关
export const searchCode = (data) => api.post('/search', data)

// 扫描相关
export const startScan = (data) => api.post('/scan', data)
export const getScanResult = (scanId) => api.get(`/scan/${scanId}`)
export const getScanFindings = (scanId) => api.get(`/scan/${scanId}/findings`)
export const listScans = () => api.get('/scans')
export const getScanInteractions = (scanId, params) => api.get(`/scan/${scanId}/interactions`, { params })
export const getScanTimeline = (scanId) => api.get(`/scan/${scanId}/timeline`)
export const getLatestInteractions = (scanId, sinceId) => api.get(`/scan/${scanId}/interactions/latest`, { params: { since_id: sinceId } })
export const getScanStats = (scanId) => api.get(`/scan/${scanId}/stats`)

// 调用图相关
export const analyzeCallGraph = (data) => api.post('/callgraph', data)

// 规则相关
export const listRules = (params) => api.get('/rules', { params })
export const getRule = (ruleId) => api.get(`/rules/${ruleId}`)

// 代码单元相关
export const listUnits = (params) => api.get('/units', { params })
export const getUnit = (unitId) => api.get(`/units/${unitId}`)

// 设置相关
export const getSettings = () => api.get('/settings')
export const updateSettings = (data) => api.post('/settings', data)
export const testLlmConnection = () => api.post('/settings/test-connection')
export const testEmbeddingConnection = () => api.post('/settings/test-embedding')

// 缓存相关
export const getCacheStats = () => api.get('/cache/stats')
export const clearCache = () => api.delete('/cache')
export const cleanupCache = () => api.post('/cache/cleanup')

// 清空索引
export const clearIndex = () => api.delete('/index')

// WebSocket 连接
export const createScanWebSocket = (scanId) => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  return new WebSocket(`${protocol}//${host}/ws/scan/${scanId}`)
}

// ============ 交互式审计 API ============

// 会话管理
export const createInteractiveSession = (data) => api.post('/interactive/session/start', data)
export const getInteractiveSession = (sessionId) => api.get(`/interactive/session/${sessionId}`)
export const deleteInteractiveSession = (sessionId) => api.delete(`/interactive/session/${sessionId}`)
export const listInteractiveSessions = () => api.get('/interactive/sessions')

// 代码浏览
export const listCodeUnits = (sessionId, limit = 200) => api.get(`/interactive/session/${sessionId}/code-units`, { params: { limit } })
export const getCodeUnitDetail = (sessionId, unitId) => api.get(`/interactive/session/${sessionId}/code-units/${unitId}`)
export const listSinkSites = (sessionId, limit = 200) => api.get(`/interactive/session/${sessionId}/sink-sites`, { params: { limit } })
export const listChainContexts = (sessionId, limit = 100) => api.get(`/interactive/session/${sessionId}/chain-contexts`, { params: { limit } })
export const getChainContextDetail = (sessionId, chainId) => api.get(`/interactive/session/${sessionId}/chain-contexts/${chainId}`)

// LLM 交互
export const analyzeSelection = (data) => api.post('/interactive/analyze', data)
export const chatWithLLM = (data) => api.post('/interactive/chat', data)
export const digDeeper = (data) => api.post('/interactive/dig-deeper', data)
export const summarizeSession = (sessionId) => api.post(`/interactive/session/${sessionId}/summarize`)
export const stopAnalysis = (sessionId) => api.post(`/interactive/session/${sessionId}/stop`)

// 发现管理
export const getFindings = (sessionId) => api.get(`/interactive/session/${sessionId}/findings`)
export const confirmFinding = (sessionId, findingId, notes = '') => api.post(`/interactive/session/${sessionId}/findings/${findingId}/confirm`, { notes })
export const rejectFinding = (sessionId, findingId, reason = '') => api.post(`/interactive/session/${sessionId}/findings/${findingId}/reject`, { reason })
export const updateFindingNotes = (sessionId, findingId, notes) => api.put(`/interactive/session/${sessionId}/findings/${findingId}/notes`, { notes })

// 交互式审计 WebSocket 连接
export const createInteractiveWebSocket = (sessionId) => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  return new WebSocket(`${protocol}//${host}/api/interactive/ws/${sessionId}`)
}

// ============ 统一智能体 API ============

// 会话管理
export const createUnifiedSession = (data) => api.post('/agent/session/create', data)
export const getUnifiedSession = (sessionId) => api.get(`/agent/session/${sessionId}`)
export const deleteUnifiedSession = (sessionId) => api.delete(`/agent/session/${sessionId}`)
export const listUnifiedSessions = (params = {}) => api.get('/agent/sessions', { params })
export const listActiveUnifiedSessions = () => api.get('/agent/sessions/active')
export const restoreUnifiedSession = (sessionId) => api.post(`/agent/session/${sessionId}/restore`)

// 对话交互
export const chatWithAgent = (sessionId, message) => api.post(`/agent/session/${sessionId}/chat`, { message })
export const getAgentMessages = (sessionId, limit = 50) => api.get(`/agent/session/${sessionId}/messages`, { params: { limit } })
export const getAgentToolCalls = (sessionId, limit = 100) => api.get(`/agent/session/${sessionId}/tool-calls`, { params: { limit } })
export const clearAgentHistory = (sessionId) => api.post(`/agent/session/${sessionId}/clear-history`)

// 工具与状态
export const getAgentTools = (sessionId, category = null) => api.get(`/agent/session/${sessionId}/tools`, { params: { category } })
export const getAgentStats = (sessionId) => api.get(`/agent/session/${sessionId}/stats`)

// 索引
export const indexAgentProject = (sessionId, data) => api.post(`/agent/session/${sessionId}/index`, data)

// 统一智能体 WebSocket 连接
export const createAgentWebSocket = (sessionId) => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  return new WebSocket(`${protocol}//${host}/api/agent/ws/${sessionId}`)
}

// ============ 代码属性图 API ============

// 图管理
export const listGraphs = () => api.get('/graph/list')
export const buildGraph = (data) => api.post('/graph/build', data)
export const getGraph = (graphId) => api.get(`/graph/${graphId}`)
export const getGraphSummary = (graphId) => api.get(`/graph/${graphId}/summary`)
export const deleteGraph = (graphId) => api.delete(`/graph/${graphId}`)

// 数据流分析
export const analyzeGraphDataFlow = (graphId, data) => api.post(`/graph/${graphId}/data-flow`, data)

// ============ 变体分析 API ============

// 模式管理
export const listVariantPatterns = () => api.get('/variant/patterns')
export const getVariantStats = () => api.get('/variant/stats')
export const confirmVulnerability = (data) => api.post('/variant/confirm', data)
export const deleteVariantPattern = (patternId) => api.delete(`/variant/patterns/${patternId}`)

// 变体搜索
export const searchVariants = (data) => api.post('/variant/search', data)
export const confirmVariant = (data) => api.post('/variant/confirm-variant', data)

// 规则管理
export const generateVariantRule = (data) => api.post('/variant/generate-rule', data)
export const approveVariantRule = (ruleId) => api.post(`/variant/rules/${ruleId}/approve`)
export const deleteVariantRule = (ruleId) => api.delete(`/variant/rules/${ruleId}`)

export default api
