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

  // 检查健康状态
  const checkHealth = async () => {
    try {
      const result = await api.checkHealth()
      isConnected.value = result.status === 'healthy'
      return result
    } catch (error) {
      isConnected.value = false
      return null
    }
  }

  // 获取索引统计
  const fetchStats = async () => {
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
  }

  // 获取扫描历史
  const fetchScanHistory = async () => {
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
  }

  // 获取规则列表
  const fetchRules = async (params = {}) => {
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
  }
})
