import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import * as api from '../api'

export const useAuditStore = defineStore('audit', () => {
  // ============ 会话状态 ============
  const currentSession = ref(null)
  const existingSessions = ref([])
  const isCreatingSession = ref(false)

  // ============ 聊天状态 ============
  const chatMessages = ref([])
  const isProcessing = ref(false)
  const currentProcessingStep = ref('')

  // ============ 工具状态 ============
  const availableTools = ref([])
  const toolCallHistory = ref([])

  // ============ 统计 ============
  const sessionStats = ref({})

  // ============ WebSocket ============
  let ws = null
  let wsReconnectTimer = null
  let wsReconnectAttempts = 0
  const WS_MAX_RECONNECT_ATTEMPTS = 5
  const WS_RECONNECT_DELAY = 3000

  // ============ 消息缓冲 (性能优化) ============
  let messageBuffer = ''
  let messageBufferTimer = null
  const MESSAGE_BUFFER_FLUSH_INTERVAL = 50  // 50ms 批量刷新

  // ============ 请求取消控制 ============
  let currentAbortController = null

  // ============ 快速扫描状态 ============
  const isQuickScanning = ref(false)
  const quickScanProgress = ref(null)
  const quickScanResult = ref(null)
  let quickScanWs = null

  // ============ 计算属性 ============
  const hasActiveSession = computed(() => !!currentSession.value)

  const sessionStatusClass = computed(() => {
    if (!currentSession.value) return ''
    const status = currentSession.value.status
    const classes = {
      ready: 'bg-green-500/20 text-green-300',
      processing: 'bg-blue-500/20 text-blue-300',
      idle: 'bg-gray-500/20 text-gray-300',
      error: 'bg-red-500/20 text-red-300',
    }
    return classes[status] || 'bg-gray-500/20 text-gray-300'
  })

  const sessionStatusDotClass = computed(() => {
    if (!currentSession.value) return ''
    const status = currentSession.value.status
    const classes = {
      ready: 'bg-green-400',
      processing: 'bg-blue-400 animate-pulse',
      idle: 'bg-gray-400',
      error: 'bg-red-400',
    }
    return classes[status] || 'bg-gray-400'
  })

  const sessionStatusText = computed(() => {
    if (!currentSession.value) return ''
    const status = currentSession.value.status
    const texts = {
      initializing: '初始化中',
      ready: '就绪',
      processing: '处理中',
      idle: '空闲',
      error: '错误',
    }
    return texts[status] || status
  })

  // ============ 会话管理方法 ============

  const fetchExistingSessions = async () => {
    try {
      const result = await api.listUnifiedSessions()
      if (result.success) {
        existingSessions.value = result.data.sessions || []
      }
    } catch (error) {
      console.error('获取会话列表失败:', error)
    }
  }

  const createSession = async (config) => {
    if (!config.targetPath) return null

    isCreatingSession.value = true
    try {
      const result = await api.createUnifiedSession({
        target_path: config.targetPath,
        languages: config.languages?.length > 0 ? config.languages : null,
        enable_call_chain: config.enableCallChain,
        enable_variant_analysis: config.enableVariantAnalysis,
      })

      if (result.success) {
        currentSession.value = result.data
        await loadSessionData(result.data.session_id)
        connectWebSocket(result.data.session_id)
        return result.data
      }
      return null
    } catch (error) {
      console.error('创建会话失败:', error)
      throw error
    } finally {
      isCreatingSession.value = false
    }
  }

  const loadSession = async (sessionId) => {
    try {
      const result = await api.getUnifiedSession(sessionId)
      if (result.success) {
        currentSession.value = result.data
        await loadSessionData(sessionId)
        connectWebSocket(sessionId)
        return result.data
      }
      return null
    } catch (error) {
      console.error('加载会话失败:', error)
      throw error
    }
  }

  const restoreSession = async (sessionId) => {
    try {
      await api.restoreUnifiedSession(sessionId)
      return await loadSession(sessionId)
    } catch (error) {
      console.error('恢复会话失败:', error)
      return await loadSession(sessionId)
    }
  }

  const loadSessionData = async (sessionId) => {
    try {
      const [toolsResult, messagesResult, toolCallsResult, statsResult] = await Promise.all([
        api.getAgentTools(sessionId),
        api.getAgentMessages(sessionId),
        api.getAgentToolCalls(sessionId),
        api.getAgentStats(sessionId),
      ])

      // 校验会话 ID，防止快速切换会话导致数据错乱
      if (!currentSession.value || currentSession.value.session_id !== sessionId) {
        return
      }

      if (toolsResult.success) {
        availableTools.value = toolsResult.data.tools || []
      }
      if (messagesResult.success) {
        chatMessages.value = (messagesResult.data.messages || []).map(m => ({
          ...m,
          timestamp: new Date(m.timestamp || Date.now()),
        }))
      }
      if (toolCallsResult.success) {
        toolCallHistory.value = toolCallsResult.data.tool_calls || []
      }
      if (statsResult.success) {
        sessionStats.value = statsResult.data || {}
      }
    } catch (error) {
      console.error('加载会话数据失败:', error)
    }
  }

  const deleteSession = async (sessionId) => {
    try {
      await api.deleteUnifiedSession(sessionId)
      existingSessions.value = existingSessions.value.filter(s => s.session_id !== sessionId)
      if (currentSession.value?.session_id === sessionId) {
        clearCurrentSession()
      }
    } catch (error) {
      console.error('删除会话失败:', error)
      throw error
    }
  }

  const clearHistory = async () => {
    if (!currentSession.value) return

    try {
      await api.clearAgentHistory(currentSession.value.session_id)
      chatMessages.value = []
      toolCallHistory.value = []
    } catch (error) {
      console.error('清空历史失败:', error)
      throw error
    }
  }

  const clearCurrentSession = () => {
    disconnectWebSocket()
    currentSession.value = null
    chatMessages.value = []
    availableTools.value = []
    toolCallHistory.value = []
    sessionStats.value = {}
    isProcessing.value = false
    currentProcessingStep.value = ''
    // 清空消息缓冲
    messageBuffer = ''
    if (messageBufferTimer) {
      clearTimeout(messageBufferTimer)
      messageBufferTimer = null
    }
  }

  // ============ 对话方法 ============

  const sendMessage = async (message) => {
    if (!message.trim() || !currentSession.value || isProcessing.value) return null

    // 取消之前未完成的请求
    cancelPendingRequest()

    // 添加用户消息
    chatMessages.value.push({
      role: 'user',
      content: message,
      timestamp: new Date(),
    })

    isProcessing.value = true
    currentProcessingStep.value = '正在分析...'

    // 创建新的 AbortController
    currentAbortController = new AbortController()

    try {
      console.log('[DEBUG] 发送 chat 请求:', currentSession.value.session_id, message)
      const result = await api.chatWithAgent(currentSession.value.session_id, message)
      console.log('[DEBUG] chat 响应:', result)

      if (result.success && result.data.message) {
        const msg = result.data.message
        chatMessages.value.push({
          role: 'assistant',
          content: msg.content,
          tool_calls: msg.tool_calls || [],
          timestamp: new Date(msg.timestamp || Date.now()),
        })

        if (msg.tool_calls && msg.tool_calls.length > 0) {
          toolCallHistory.value.push(...msg.tool_calls)
        }

        sessionStats.value.total_llm_calls = (sessionStats.value.total_llm_calls || 0) + 1

        return msg
      }
      return null
    } catch (error) {
      if (error.name === 'AbortError' || error.name === 'CanceledError') {
        console.log('请求已取消')
        return null
      }
      console.error('对话失败:', error)
      chatMessages.value.push({
        role: 'assistant',
        content: '处理失败: ' + (error.response?.data?.detail || error.message),
        timestamp: new Date(),
      })
      throw error
    } finally {
      isProcessing.value = false
      currentProcessingStep.value = ''
      currentAbortController = null
    }
  }

  const cancelPendingRequest = () => {
    if (currentAbortController) {
      currentAbortController.abort()
      currentAbortController = null
    }
    isProcessing.value = false
    currentProcessingStep.value = ''
  }

  // 检查并恢复 WebSocket 连接（用于页面返回时）
  const ensureWebSocketConnected = () => {
    if (currentSession.value && (!ws || ws.readyState !== WebSocket.OPEN)) {
      console.log('[AuditStore] 恢复 WebSocket 连接:', currentSession.value.session_id)
      wsReconnectAttempts = 0  // 恢复连接时重置重试计数
      connectWebSocket(currentSession.value.session_id)
    }
  }

  // ============ WebSocket 方法 ============

  const connectWebSocket = (sessionId) => {
    if (wsReconnectTimer) {
      clearTimeout(wsReconnectTimer)
      wsReconnectTimer = null
    }

    try {
      if (ws) {
        ws.close()
        ws = null
      }

      ws = api.createAgentWebSocket(sessionId)

      ws.onopen = () => {
        console.log('Agent WebSocket connected')
        wsReconnectAttempts = 0
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          handleWebSocketMessage(data)
        } catch (e) {
          console.error('WebSocket message parse error:', e)
        }
      }

      ws.onerror = (error) => {
        console.error('WebSocket error:', error)
      }

      ws.onclose = (event) => {
        console.log('WebSocket disconnected, code:', event.code)
        // 只有当会话 ID 匹配且非正常关闭时才重连
        const isCurrentSession = currentSession.value && currentSession.value.session_id === sessionId
        if (isCurrentSession && event.code !== 1000 && wsReconnectAttempts < WS_MAX_RECONNECT_ATTEMPTS) {
          wsReconnectAttempts++
          wsReconnectTimer = setTimeout(() => {
            connectWebSocket(sessionId)
          }, WS_RECONNECT_DELAY)
        }
      }
    } catch (error) {
      console.error('WebSocket connection failed:', error)
    }
  }

  const disconnectWebSocket = () => {
    if (wsReconnectTimer) {
      clearTimeout(wsReconnectTimer)
      wsReconnectTimer = null
    }
    wsReconnectAttempts = 0

    if (ws) {
      ws.close(1000, 'User disconnect')
      ws = null
    }
  }

  // 批量刷新消息缓冲到 UI，减少渲染频率
  const flushMessageBuffer = () => {
    if (!messageBuffer) return

    const lastMsg = chatMessages.value[chatMessages.value.length - 1]
    if (lastMsg && lastMsg.role === 'assistant' && lastMsg._streaming) {
      lastMsg.content += messageBuffer
    } else {
      chatMessages.value.push({
        role: 'assistant',
        content: messageBuffer,
        tool_calls: [],
        timestamp: new Date(),
        _streaming: true,
      })
    }
    messageBuffer = ''
  }

  const handleWebSocketMessage = (data) => {
    switch (data.type) {
      case 'connected':
        console.log('WebSocket connected:', data)
        break
      case 'tool_call_start':
        currentProcessingStep.value = `调用工具: ${data.data?.tool_name || ''}`
        if (currentSession.value) currentSession.value.status = 'processing'
        break
      case 'tool_call_end':
        if (data.data) {
          toolCallHistory.value.push(data.data)
        }
        break
      case 'message_chunk':
        // 使用缓冲批量更新，减少高频 UI 渲染
        if (data.data?.content) {
          messageBuffer += data.data.content
          if (!messageBufferTimer) {
            messageBufferTimer = setTimeout(() => {
              flushMessageBuffer()
              messageBufferTimer = null
            }, MESSAGE_BUFFER_FLUSH_INTERVAL)
          }
        }
        break
      case 'message_complete':
        // 确保刷新剩余缓冲内容
        if (messageBufferTimer) {
          clearTimeout(messageBufferTimer)
          messageBufferTimer = null
        }
        flushMessageBuffer()

        if (data.data) {
          const lastMsg = chatMessages.value[chatMessages.value.length - 1]
          if (lastMsg && lastMsg._streaming) {
            lastMsg.content = data.data.content
            lastMsg.tool_calls = data.data.tool_calls || []
            delete lastMsg._streaming
          } else {
            chatMessages.value.push({
              role: 'assistant',
              content: data.data.content,
              tool_calls: data.data.tool_calls || [],
              timestamp: new Date(),
            })
          }
        }
        isProcessing.value = false
        currentProcessingStep.value = ''
        if (currentSession.value) currentSession.value.status = 'ready'
        break
      case 'error':
        console.error('WebSocket error:', data.data?.error)
        isProcessing.value = false
        currentProcessingStep.value = ''
        break
    }
  }

  // ============ 快速扫描方法 ============

  const startQuickScan = async (config) => {
    if (isQuickScanning.value) return null

    isQuickScanning.value = true
    quickScanProgress.value = { progress: 0, current_step: '正在初始化...' }
    quickScanResult.value = null

    try {
      const result = await api.startScan(config)

      if (result.success && result.data.scan_id) {
        connectQuickScanWebSocket(result.data.scan_id)
        return result.data.scan_id
      } else {
        throw new Error(result.error || '启动扫描失败')
      }
    } catch (error) {
      console.error('快速扫描失败:', error)
      isQuickScanning.value = false
      quickScanProgress.value = null
      throw error
    }
  }

  const connectQuickScanWebSocket = (scanId) => {
    try {
      if (quickScanWs) {
        quickScanWs.close()
        quickScanWs = null
      }

      quickScanWs = api.createScanWebSocket(scanId)

      quickScanWs.onopen = () => {
        console.log('Quick scan WebSocket connected')
      }

      quickScanWs.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          handleQuickScanMessage(data)
        } catch (e) {
          console.error('Quick scan WebSocket parse error:', e)
        }
      }

      quickScanWs.onerror = (error) => {
        console.error('Quick scan WebSocket error:', error)
      }

      quickScanWs.onclose = () => {
        console.log('Quick scan WebSocket closed')
      }
    } catch (error) {
      console.error('Quick scan WebSocket connection failed:', error)
      isQuickScanning.value = false
    }
  }

  const handleQuickScanMessage = (data) => {
    switch (data.type) {
      case 'progress':
        // 检查是否实际上是完成状态
        if (data.status === 'completed') {
          quickScanResult.value = {
            scan_id: data.scan_id,
            findings_count: data.findings_count || 0,
            target_path: data.target_path,
          }
          isQuickScanning.value = false
          quickScanProgress.value = null
          disconnectQuickScanWebSocket()
        } else if (data.status === 'failed') {
          console.error('Scan failed:', data.current_step)
          isQuickScanning.value = false
          quickScanProgress.value = null
          disconnectQuickScanWebSocket()
        } else {
          quickScanProgress.value = {
            progress: data.progress || 0,
            current_step: data.current_step || '扫描中...',
            details: data.details || '',
          }
        }
        break
      case 'completed':
        quickScanResult.value = {
          scan_id: data.scan_id,
          findings_count: data.findings_count || 0,
          target_path: data.target_path,
        }
        isQuickScanning.value = false
        quickScanProgress.value = null
        disconnectQuickScanWebSocket()
        break
      case 'error':
        console.error('Scan error:', data.error)
        isQuickScanning.value = false
        quickScanProgress.value = null
        disconnectQuickScanWebSocket()
        break
    }
  }

  const disconnectQuickScanWebSocket = () => {
    if (quickScanWs) {
      quickScanWs.close(1000, 'Scan completed')
      quickScanWs = null
    }
  }

  const clearQuickScanResult = () => {
    quickScanResult.value = null
  }

  // ============ 清理方法 ============

  const cleanup = () => {
    cancelPendingRequest()
    disconnectWebSocket()
    disconnectQuickScanWebSocket()
  }

  return {
    // 会话状态
    currentSession,
    existingSessions,
    isCreatingSession,
    hasActiveSession,
    sessionStatusClass,
    sessionStatusDotClass,
    sessionStatusText,

    // 聊天状态
    chatMessages,
    isProcessing,
    currentProcessingStep,

    // 工具状态
    availableTools,
    toolCallHistory,

    // 统计
    sessionStats,

    // 快速扫描
    isQuickScanning,
    quickScanProgress,
    quickScanResult,

    // 会话方法
    fetchExistingSessions,
    createSession,
    loadSession,
    restoreSession,
    deleteSession,
    clearHistory,
    clearCurrentSession,

    // 对话方法
    sendMessage,
    cancelPendingRequest,

    // WebSocket
    connectWebSocket,
    disconnectWebSocket,
    ensureWebSocketConnected,

    // 快速扫描方法
    startQuickScan,
    clearQuickScanResult,

    // 清理
    cleanup,
  }
})
