import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import * as api from '../api'

export const useAppStore = defineStore('app', () => {
  // 状态
  const isConnected = ref(false)
  const stats = ref({
    totalUnits: 0,
    collectionName: '',
    languages: {},
    unitTypes: {},
  })
  const currentScan = ref(null)
  const scanHistory = ref([])
  const rules = ref([])

  // ============ 请求去重与缓存机制 ============
  // 存储正在进行的请求 Promise，避免并发重复请求
  const pendingRequests = {}
  // 缓存时间戳，用于判断缓存是否过期
  const cacheTimestamps = {}
  // 缓存有效期（毫秒）
  const CACHE_TTL = {
    health: 5000,       // 健康检查 5 秒
    stats: 30000,       // 统计信息 30 秒
    scanHistory: 10000, // 扫描历史 10 秒
    rules: 60000,       // 规则列表 60 秒
  }

  // 通用的带缓存和去重的请求封装
  const cachedRequest = async (key, ttl, fetcher, forceRefresh = false) => {
    const now = Date.now()

    // 如果有未过期的缓存且不强制刷新，直接返回
    if (!forceRefresh && cacheTimestamps[key] && (now - cacheTimestamps[key] < ttl)) {
      return { cached: true }
    }

    // 如果有正在进行的相同请求，复用它
    if (pendingRequests[key]) {
      return pendingRequests[key]
    }

    // 发起新请求
    pendingRequests[key] = fetcher()
      .finally(() => {
        delete pendingRequests[key]
      })

    const result = await pendingRequests[key]
    if (result) {
      cacheTimestamps[key] = now
    }
    return result
  }

  // 检查健康状态（带去重和缓存）
  const checkHealth = async (forceRefresh = false) => {
    return cachedRequest('health', CACHE_TTL.health, async () => {
      try {
        const result = await api.checkHealth()
        isConnected.value = result.status === 'healthy'
        return result
      } catch (error) {
        isConnected.value = false
        return null
      }
    }, forceRefresh)
  }

  // 获取索引统计（带去重和缓存）
  const fetchStats = async (forceRefresh = false) => {
    return cachedRequest('stats', CACHE_TTL.stats, async () => {
      try {
        const result = await api.getIndexStats()
        if (result.success) {
          stats.value = {
            totalUnits: result.data.total_units,
            collectionName: result.data.collection_name,
            languages: result.data.languages || {},
            unitTypes: result.data.unit_types || {},
          }
        }
        return result
      } catch (error) {
        console.error('Failed to fetch stats:', error)
        return null
      }
    }, forceRefresh)
  }

  // 获取扫描历史（带去重和缓存）
  const fetchScanHistory = async (forceRefresh = false) => {
    return cachedRequest('scanHistory', CACHE_TTL.scanHistory, async () => {
      try {
        const result = await api.listScans()
        if (result.success) {
          scanHistory.value = result.data
        }
        return result
      } catch (error) {
        console.error('Failed to fetch scan history:', error)
        return null
      }
    }, forceRefresh)
  }

  // 获取规则列表（带去重和缓存）
  const fetchRules = async (params = {}, forceRefresh = false) => {
    // 规则请求带参数时，key 需要包含参数
    const key = 'rules:' + JSON.stringify(params)
    return cachedRequest(key, CACHE_TTL.rules, async () => {
      try {
        const result = await api.listRules(params)
        if (result.success) {
          rules.value = result.data.rules
        }
        return result
      } catch (error) {
        console.error('Failed to fetch rules:', error)
        return null
      }
    }, forceRefresh)
  }

  // 使缓存失效（用于数据变更后强制刷新）
  const invalidateCache = (key) => {
    if (key) {
      delete cacheTimestamps[key]
    } else {
      // 清空所有缓存
      Object.keys(cacheTimestamps).forEach(k => delete cacheTimestamps[k])
    }
  }

  // 开始扫描
  const startScan = async (config) => {
    try {
      const result = await api.startScan(config)
      if (result.success) {
        currentScan.value = {
          scanId: result.data.scan_id,
          status: 'pending',
          progress: 0,
        }
      }
      return result
    } catch (error) {
      console.error('Failed to start scan:', error)
      return null
    }
  }

  // 获取扫描结果
  const fetchScanResult = async (scanId) => {
    try {
      const result = await api.getScanResult(scanId)
      if (result.success) {
        currentScan.value = result.data
      }
      return result
    } catch (error) {
      console.error('Failed to fetch scan result:', error)
      return null
    }
  }

  return {
    // 状态
    isConnected,
    stats,
    currentScan,
    scanHistory,
    rules,

    // 方法
    checkHealth,
    fetchStats,
    fetchScanHistory,
    fetchRules,
    startScan,
    fetchScanResult,
    invalidateCache,
  }
})
