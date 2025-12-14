import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 60000,
})

// 响应拦截器
api.interceptors.response.use(
  (response) => response.data,
  (error) => {
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

export default api
