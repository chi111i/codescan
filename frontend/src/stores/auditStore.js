import { defineStore } from 'pinia'
import { ref, shallowRef, computed, triggerRef } from 'vue'
import * as api from '../api'

export const useAuditStore = defineStore('audit', () => {
  // ============ 会话状态 ============
  const currentSession = ref(null)
  // 使用 shallowRef 减少大型数组的响应式开销
  const existingSessions = shallowRef([])
  const isCreatingSession = ref(false)

  // ============ 聊天状态 ============
  // 使用 shallowRef - 聊天消息通常整体替换或追加
  const chatMessages = shallowRef([])
  const isProcessing = ref(false)
  const currentProcessingStep = ref('')

  // ============ 工具状态 ============
  const availableTools = shallowRef([])
  const toolCallHistory = shallowRef([])

  // ============ 统计 ============
  const sessionStats = ref({})

  // ============ WebSocket ============
  let ws = null
  let wsReconnectTimer = null
  let wsReconnectAttempts = 0
  const WS_MAX_RECONNECT_ATTEMPTS = 5
  const WS_RECONNECT_DELAY = 3000

  // ============ 心跳检测 ============
  let wsHeartbeatTimer = null
  let wsLastPongTime = 0
  const WS_HEARTBEAT_INTERVAL = 30000  // 30秒发送一次心跳
  const WS_HEARTBEAT_TIMEOUT = 10000   // 10秒内未收到响应则认为断连

  // 标记是否为"主动关闭"（用于避免页面切换时触发自动重连）
  // 说明：浏览器 WebSocket 的 close 事件有时会返回非 1000（例如 1006），
  // 如果不区分主动关闭，会导致切页后仍在后台不断重连、解析消息，进而造成卡顿。
  // 这里通过给具体 ws 实例挂载 __manualClose 标记来避免竞态。

  // ============ 消息缓冲 (性能优化) ============
  let messageBuffer = ''
  let messageBufferTimer = null
  const MESSAGE_BUFFER_FLUSH_INTERVAL = 50  // 50ms 批量刷新

  // ============ 请求取消控制 ============
  let currentAbortController = null
  let sessionsAbortController = null  // 会话列表请求的取消控制器
  let sessionsLastFetchTime = 0  // 会话列表上次获取时间
  const SESSIONS_CACHE_TTL = 10000  // 会话列表缓存有效期 10 秒

  // ============ 快速扫描状态 ============
  const isQuickScanning = ref(false)
  const quickScanProgress = ref(null)
  const quickScanResult = ref(null)
  let quickScanWs = null

  // ============ LLM 调用过程状态 (实时展示) ============
  // 使用 shallowRef 减少大型数组的响应式追踪开销
  const llmCallHistory = shallowRef([])  // LLM 调用历史 [{call_id, status, content_preview, tool_calls, ...}]
  const currentLlmCall = ref(null)  // 当前正在进行的 LLM 调用
  const isLlmThinking = ref(false)  // LLM 是否正在思考

  // ============ 实时发现状态 ============
  const realtimeFindings = shallowRef([])  // 实时发现的漏洞列表
  const analysisProgress = ref(null)  // 分析进度 {current, total, current_site}

  // ============ Function Calling 状态 ============
  const fcState = ref({
    enabled: false,
    status: 'idle', // idle, analyzing, completed, failed
    currentSink: '',
    currentTurn: 0,
    totalToolCalls: 0,
    toolCalls: [],
    findingsCount: 0,
  })

  // 重置 FC 状态
  const resetFCState = () => {
    fcState.value = {
      enabled: false,
      status: 'idle',
      currentSink: '',
      currentTurn: 0,
      totalToolCalls: 0,
      toolCalls: [],
      findingsCount: 0,
    }
  }

  // 更新 FC 状态
  const updateFCState = (updates) => {
    Object.assign(fcState.value, updates)
  }

  // 添加 FC 工具调用
  const addFCToolCall = (toolCall) => {
    fcState.value.toolCalls.push(toolCall)
    fcState.value.totalToolCalls++
  }

  // 更新 FC 工具调用状态
  const updateFCToolCallStatus = (toolName, status, result = null, error = null) => {
    const existing = fcState.value.toolCalls.find(
      tc => tc.tool_name === toolName && tc.status === 'running'
    )
    if (existing) {
      existing.status = status
      if (result !== null) {
        existing.result = result
      }
      if (error !== null) {
        existing.error = error
      }
    }
  }

  // ============ ShallowRef 更新辅助函数 ============
  // shallowRef 只追踪 .value 的引用变化，push/splice 等操作需要手动触发更新

  /**
   * 向 shallowRef 数组追加元素并触发更新
   */
  const pushToShallowRef = (shallowRefArray, ...items) => {
    shallowRefArray.value.push(...items)
    triggerRef(shallowRefArray)
  }

  /**
   * 替换 shallowRef 数组内容
   */
  const replaceShallowRef = (shallowRefArray, newArray) => {
    shallowRefArray.value = newArray
    // 赋值操作已经触发更新，不需要 triggerRef
  }

  /**
   * 添加聊天消息（带限制）
   */
  const addChatMessage = (message) => {
    const MAX_MESSAGES = 500
    if (chatMessages.value.length >= MAX_MESSAGES) {
      chatMessages.value = chatMessages.value.slice(-MAX_MESSAGES + 1)
    }
    chatMessages.value.push(message)
    triggerRef(chatMessages)
  }

  /**
   * 添加工具调用历史（带限制）
   */
  const addToolCallHistory = (...toolCalls) => {
    const MAX_TOOL_CALLS = 200
    if (toolCallHistory.value.length >= MAX_TOOL_CALLS) {
      toolCallHistory.value = toolCallHistory.value.slice(-MAX_TOOL_CALLS + toolCalls.length)
    }
    toolCallHistory.value.push(...toolCalls)
    triggerRef(toolCallHistory)
  }

  /**
   * 添加实时发现（带限制和去重）
   */
  const addRealtimeFinding = (finding) => {
    const MAX_FINDINGS = 100
    // 去重检查
    const exists = realtimeFindings.value.some(f =>
      f.id === finding.id ||
      (f.file_path === finding.file_path && f.line_start === finding.line_start)
    )
    if (!exists) {
      if (realtimeFindings.value.length >= MAX_FINDINGS) {
        realtimeFindings.value = realtimeFindings.value.slice(-MAX_FINDINGS + 1)
      }
      realtimeFindings.value.push(finding)
      triggerRef(realtimeFindings)
    }
  }

  /**
   * 添加 LLM 调用历史
   */
  const addLlmCallHistory = (call) => {
    const MAX_LLM_CALLS = 100
    if (llmCallHistory.value.length >= MAX_LLM_CALLS) {
      llmCallHistory.value = llmCallHistory.value.slice(-MAX_LLM_CALLS + 1)
    }
    llmCallHistory.value.push(call)
    triggerRef(llmCallHistory)
  }

  // 生成唯一的工具调用 ID
  const generateToolCallId = () => {
    return `tc_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`
  }

  /**
   * 处理 FC 工具调用 WebSocket 消息
   * 此函数可被外部组件复用，避免代码重复
   *
   * @param {Object} data - WebSocket 消息数据
   * @param {string} data.type - 消息类型 (应为 'fc_tool_call')
   * @param {string} [data.sink_symbol] - 当前分析的 sink 符号
   * @param {Object} [data.tool_call] - 工具调用信息
   * @param {string} [data.status] - 外层状态
   * @param {string} [data.timestamp] - 时间戳
   * @param {Object} [targetState] - 可选的目标状态对象，默认使用 store 的 fcState
   * @returns {Object} 处理后的工具调用对象
   */
  const processFCToolCallMessage = (data, targetState = null) => {
    const state = targetState || fcState.value

    // 更新基础状态
    state.enabled = true
    state.status = 'analyzing'
    if (data.sink_symbol) {
      state.currentSink = data.sink_symbol
    }

    // 解析工具调用数据
    const toolCall = data.tool_call || {}
    const toolStatus = toolCall.status || data.status || 'running'
    const isStarting = (toolStatus === 'running' || toolStatus === 'pending')
    const isEnded = (toolStatus === 'success' || toolStatus === 'failed')

    // 构建工具调用记录
    const toolCallRecord = {
      id: toolCall.id || generateToolCallId(),
      tool_name: toolCall.tool_name || toolCall.name || 'unknown',
      status: toolStatus,
      arguments: toolCall.arguments || {},
      result: toolCall.result || null,
      error: toolCall.error || null,
      duration_ms: toolCall.duration_ms || 0,
      timestamp: data.timestamp || new Date().toISOString(),
    }

    if (isStarting) {
      // 工具调用开始: 添加新记录
      toolCallRecord.status = 'running'
      state.toolCalls.push(toolCallRecord)
      state.totalToolCalls = state.toolCalls.length
    } else if (isEnded) {
      // 工具调用结束: 更新已有记录或添加新记录
      const existingCall = state.toolCalls.find(
        tc => tc.id === toolCall.id || (tc.tool_name === toolCallRecord.tool_name && tc.status === 'running')
      )
      if (existingCall) {
        existingCall.status = toolStatus
        existingCall.result = toolCall.result
        existingCall.error = toolCall.error
        existingCall.duration_ms = toolCall.duration_ms || 0
      } else {
        // 没找到 running 状态的记录，直接添加完整记录
        state.toolCalls.push(toolCallRecord)
        state.totalToolCalls = state.toolCalls.length
      }
    }

    return toolCallRecord
  }

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

  const fetchExistingSessions = async (forceRefresh = false) => {
    const now = Date.now()

    // 如果缓存有效且不强制刷新，跳过请求
    if (!forceRefresh && existingSessions.value.length > 0 && (now - sessionsLastFetchTime < SESSIONS_CACHE_TTL)) {
      return
    }

    // 取消之前的请求
    if (sessionsAbortController) {
      sessionsAbortController.abort()
    }
    sessionsAbortController = new AbortController()

    try {
      const result = await api.listUnifiedSessions({ signal: sessionsAbortController.signal })
      if (result.success) {
        existingSessions.value = result.data.sessions || []
        sessionsLastFetchTime = now
      }
    } catch (error) {
      // 忽略取消错误
      if (error.name !== 'AbortError' && error.name !== 'CanceledError') {
        console.error('获取会话列表失败:', error)
      }
    } finally {
      sessionsAbortController = null
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

  // 会话加载的 AbortController
  let sessionLoadAbortController = null

  const loadSession = async (sessionId) => {
    // 取消之前的加载请求
    if (sessionLoadAbortController) {
      sessionLoadAbortController.abort()
    }
    sessionLoadAbortController = new AbortController()
    const signal = sessionLoadAbortController.signal

    try {
      const result = await api.getUnifiedSession(sessionId, { signal })
      if (signal.aborted) return null  // 检查是否已被取消

      if (result.success) {
        currentSession.value = result.data
        await loadSessionData(sessionId, signal)
        if (!signal.aborted) {
          connectWebSocket(sessionId)
        }
        return result.data
      }
      return null
    } catch (error) {
      if (error.name === 'AbortError' || error.name === 'CanceledError') {
        console.log('[loadSession] 请求已取消')
        return null
      }
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

  const loadSessionData = async (sessionId, signal = null) => {
    try {
      // M-8 修复: 使用 Promise.allSettled 防止单个请求失败导致全部失败
      const results = await Promise.allSettled([
        api.getAgentTools(sessionId),
        api.getAgentMessages(sessionId),
        api.getAgentToolCalls(sessionId),
        api.getAgentStats(sessionId),
      ])

      // 提取成功的结果（失败的返回 undefined）
      const [toolsResult, messagesResult, toolCallsResult, statsResult] = results.map(
        r => r.status === 'fulfilled' ? r.value : { success: false }
      )

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
    // 清空 LLM 调用历史和实时发现
    llmCallHistory.value = []
    currentLlmCall.value = null
    isLlmThinking.value = false
    realtimeFindings.value = []
    analysisProgress.value = null
    // 清空 FC 状态
    resetFCState()
  }

  // ============ 对话方法 ============

  const sendMessage = async (message) => {
    if (!message.trim() || !currentSession.value || isProcessing.value) return null

    // 确保 WebSocket 已连接（在发送消息前）
    ensureWebSocketConnected()

    // 取消之前未完成的请求
    cancelPendingRequest()

    // 添加用户消息
    addChatMessage({
      role: 'user',
      content: message,
      timestamp: new Date(),
    })

    isProcessing.value = true
    currentProcessingStep.value = '正在分析...'

    // 创建新的 AbortController
    // 重要：必须把 signal 传给 axios 才能真正取消请求，否则“取消/切页”后请求仍会继续，
    // 可能导致页面切换卡顿、回包写入 store 等问题。
    currentAbortController = new AbortController()

    // 等待 WebSocket 连接就绪（最多等待 2 秒）
    const wsConnected = await waitForWebSocketReady(2000)
    if (!wsConnected) {
      console.warn('[AuditStore] WebSocket 未能及时连接，但将继续发送请求')
    }

    try {
      console.log('[DEBUG] 发送 chat 请求:', currentSession.value.session_id, message)
      const result = await api.chatWithAgent(
        currentSession.value.session_id,
        message,
        { signal: currentAbortController.signal }
      )
      console.log('[DEBUG] chat 响应:', result)

      if (result.success && result.data.message) {
        const msg = result.data.message
        addChatMessage({
          role: 'assistant',
          content: msg.content,
          tool_calls: msg.tool_calls || [],
          timestamp: new Date(msg.timestamp || Date.now()),
        })

        if (msg.tool_calls && msg.tool_calls.length > 0) {
          addToolCallHistory(...msg.tool_calls)
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
      addChatMessage({
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
  // 修复：只在 WebSocket 不存在时重连（disconnectWebSocket 已确保 ws = null）
  const ensureWebSocketConnected = () => {
    // ws 已被 disconnectWebSocket 立即设为 null，所以这里只需检查 ws 是否为 null
    if (currentSession.value && !ws) {
      console.log('[AuditStore] 恢复 WebSocket 连接:', currentSession.value.session_id)
      wsReconnectAttempts = 0  // 恢复连接时重置重试计数
      connectWebSocket(currentSession.value.session_id)
    }
  }

  // 等待 WebSocket 连接就绪
  const waitForWebSocketReady = (timeoutMs = 2000) => {
    return new Promise((resolve) => {
      // 如果已经连接，立即返回
      if (ws && ws.readyState === WebSocket.OPEN) {
        resolve(true)
        return
      }

      const startTime = Date.now()
      const checkInterval = 50  // 50ms 检查一次

      const checkConnection = () => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          resolve(true)
          return
        }

        if (Date.now() - startTime >= timeoutMs) {
          resolve(false)
          return
        }

        setTimeout(checkConnection, checkInterval)
      }

      checkConnection()
    })
  }

  // ============ WebSocket 方法 ============

  const connectWebSocket = (sessionId) => {
    // 清除重连和心跳定时器
    if (wsReconnectTimer) {
      clearTimeout(wsReconnectTimer)
      wsReconnectTimer = null
    }
    if (wsHeartbeatTimer) {
      clearInterval(wsHeartbeatTimer)
      wsHeartbeatTimer = null
    }

    try {
      if (ws) {
        // 关闭旧连接：标记为主动关闭，避免 onclose 触发自动重连
        try {
          ws.__manualClose = true
          ws.onopen = null
          ws.onmessage = null
          ws.onerror = null
          ws.onclose = null
          ws.close(1000, 'Reconnecting')
        } catch (e) {
          // ignore
        }
        ws = null
      }

      const wsInstance = api.createAgentWebSocket(sessionId)
      // 给具体实例打标记，避免竞态（旧 ws close 事件晚到）
      wsInstance.__manualClose = false
      ws = wsInstance

      wsInstance.onopen = () => {
        console.log('Agent WebSocket connected')
        wsReconnectAttempts = 0
        wsLastPongTime = Date.now()

        // 启动心跳检测
        wsHeartbeatTimer = setInterval(() => {
          if (!ws || ws.readyState !== WebSocket.OPEN) {
            return
          }
          // 检查上次响应时间
          const now = Date.now()
          if (wsLastPongTime && now - wsLastPongTime > WS_HEARTBEAT_INTERVAL + WS_HEARTBEAT_TIMEOUT) {
            console.warn('[WebSocket] 心跳超时，尝试重连...')
            ws.__manualClose = true
            ws.close(4000, 'Heartbeat timeout')
            if (currentSession.value) {
              connectWebSocket(currentSession.value.session_id)
            }
            return
          }
          // 发送心跳（如果后端支持）
          try {
            ws.send(JSON.stringify({ type: 'ping', timestamp: now }))
          } catch (e) {
            // 发送失败，可能连接已断开
          }
        }, WS_HEARTBEAT_INTERVAL)
      }

      wsInstance.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          // 更新心跳时间（任何消息都视为活跃）
          wsLastPongTime = Date.now()
          // 处理 pong 响应（静默处理）
          if (data.type === 'pong') {
            return
          }
          handleWebSocketMessage(data)
        } catch (e) {
          console.error('WebSocket message parse error:', e)
        }
      }

      wsInstance.onerror = (error) => {
        console.error('WebSocket error:', error)
      }

      wsInstance.onclose = (event) => {
        console.log('WebSocket disconnected, code:', event.code)
        // 清除心跳定时器
        if (wsHeartbeatTimer) {
          clearInterval(wsHeartbeatTimer)
          wsHeartbeatTimer = null
        }
        // 主动关闭时，清理 ws 引用并返回，不进行重连
        if (wsInstance.__manualClose) {
          // 只有当这个实例是当前的 ws 时才清理
          if (ws === wsInstance) {
            ws = null
          }
          return
        }
        // 只有当会话 ID 匹配且非正常关闭时才重连
        const isCurrentSession = currentSession.value && currentSession.value.session_id === sessionId
        if (isCurrentSession && event.code !== 1000 && wsReconnectAttempts < WS_MAX_RECONNECT_ATTEMPTS) {
          wsReconnectAttempts++
          const delay = WS_RECONNECT_DELAY * Math.pow(1.5, wsReconnectAttempts - 1)  // 指数退避
          console.log(`[WebSocket] 将在 ${delay}ms 后尝试重连 (第 ${wsReconnectAttempts} 次)`)
          wsReconnectTimer = setTimeout(() => {
            connectWebSocket(sessionId)
          }, delay)
        }
      }
    } catch (error) {
      console.error('WebSocket connection failed:', error)
    }
  }

  const disconnectWebSocket = () => {
    // 清除重连定时器
    if (wsReconnectTimer) {
      clearTimeout(wsReconnectTimer)
      wsReconnectTimer = null
    }
    wsReconnectAttempts = 0

    // 清除心跳定时器
    if (wsHeartbeatTimer) {
      clearInterval(wsHeartbeatTimer)
      wsHeartbeatTimer = null
    }

    // 清除消息缓冲定时器（防止页面切换后仍尝试更新状态）
    if (messageBufferTimer) {
      clearTimeout(messageBufferTimer)
      messageBufferTimer = null
    }
    messageBuffer = ''

    // 关闭 WebSocket
    // 修复：立即清除所有事件处理器并将 ws 设为 null
    // 这确保页面切换时不会阻塞等待 WebSocket 关闭完成
    // 关键优化：不等待 close 握手完成，直接释放引用
    if (ws) {
      const wsToClose = ws
      ws = null  // 立即释放引用，避免阻塞
      try {
        wsToClose.__manualClose = true
        // 清除所有事件处理器，避免关闭后仍触发回调
        wsToClose.onopen = null
        wsToClose.onmessage = null
        wsToClose.onerror = null
        wsToClose.onclose = null
        // 调用 close，但不等待完成
        wsToClose.close(1000, 'User disconnect')
      } catch (e) {
        // ignore - WebSocket 可能已经关闭
      }
    }

    // 重置处理状态（防止页面切换后卡在处理中状态）
    isProcessing.value = false
    currentProcessingStep.value = ''
    isLlmThinking.value = false
    currentLlmCall.value = null
  }

  // 批量刷新消息缓冲到 UI，减少渲染频率
  const flushMessageBuffer = () => {
    if (!messageBuffer) return

    const lastMsg = chatMessages.value[chatMessages.value.length - 1]
    if (lastMsg && lastMsg.role === 'assistant' && lastMsg._streaming) {
      lastMsg.content += messageBuffer
      triggerRef(chatMessages)  // 手动触发更新
    } else {
      addChatMessage({
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
          addToolCallHistory(data.data)
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
            triggerRef(chatMessages)  // 手动触发更新
          } else {
            addChatMessage({
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

      // === LLM 调用过程事件 (实时展示) ===
      case 'llm_call_start':
        isLlmThinking.value = true
        currentLlmCall.value = {
          call_id: data.data?.call_id,
          status: 'thinking',
          messages_count: data.data?.messages_count,
          tools_count: data.data?.tools_count,
          current_question: data.data?.current_question,
          started_at: data.data?.timestamp || new Date().toISOString(),
        }
        currentProcessingStep.value = 'LLM 正在思考...'
        break

      case 'llm_call_end':
        isLlmThinking.value = false
        if (currentLlmCall.value) {
          currentLlmCall.value.status = 'completed'
          currentLlmCall.value.content_preview = data.data?.content_preview || ''
          currentLlmCall.value.content = data.data?.content || ''
          currentLlmCall.value.tool_calls = data.data?.tool_calls || []
          currentLlmCall.value.tool_calls_count = data.data?.tool_calls_count || 0
          currentLlmCall.value.usage = data.data?.usage
          currentLlmCall.value.finished_at = data.data?.timestamp || new Date().toISOString()
          // 添加到历史记录
          llmCallHistory.value.push({ ...currentLlmCall.value })
          // 限制历史记录数量 (最近50条)
          if (llmCallHistory.value.length > 50) {
            llmCallHistory.value.shift()
          }
          // 重置当前调用状态，为下一次调用做准备
          currentLlmCall.value = null
        }
        currentProcessingStep.value = data.data?.tool_calls_count > 0
          ? `执行 ${data.data.tool_calls_count} 个工具调用`
          : '处理响应中...'
        break

      case 'llm_thinking':
        // 可选：流式思考内容
        if (data.data?.content) {
          if (currentLlmCall.value) {
            currentLlmCall.value.thinking_content = (currentLlmCall.value.thinking_content || '') + data.data.content
          }
        }
        break

      // === 漏洞发现事件 ===
      case 'new_finding':
        if (data.data) {
          const findingId = data.data.id  // 保存到局部变量避免闭包问题
          // 添加到实时发现列表顶部
          realtimeFindings.value.unshift({
            ...data.data,
            _isNew: true,  // 标记为新发现（用于高亮）
            received_at: new Date().toISOString(),
          })
          // 限制显示数量 (最近100条)
          if (realtimeFindings.value.length > 100) {
            realtimeFindings.value.pop()
          }
          // 3秒后移除新发现标记
          if (findingId) {
            setTimeout(() => {
              const finding = realtimeFindings.value.find(f => f.id === findingId)
              if (finding) finding._isNew = false
            }, 3000)
          }
        }
        break

      // === 分析进度事件 ===
      case 'analysis_progress':
        analysisProgress.value = {
          current: data.data?.current || 0,
          total: data.data?.total || 0,
          current_site: data.data?.current_site || null,
          percentage: data.data?.total > 0
            ? Math.round((data.data.current / data.data.total) * 100)
            : 0,
        }
        currentProcessingStep.value = `分析触发点 ${data.data?.current || 0}/${data.data?.total || 0}`
        break

      // === Function Calling 事件 ===
      case 'fc_tool_call':
        // 使用统一的 processFCToolCallMessage 处理函数
        processFCToolCallMessage(data)
        break

      case 'fc_llm_thinking':
        fcState.value.enabled = true
        fcState.value.status = 'analyzing'
        if (data.sink_symbol) {
          fcState.value.currentSink = data.sink_symbol
        }
        if (data.message) {
          currentProcessingStep.value = data.message
        }
        break

      case 'fc_turn_complete':
        if (data.turn !== undefined) {
          fcState.value.currentTurn = data.turn
        }
        break

      case 'fc_analysis_complete':
        fcState.value.status = data.success ? 'completed' : 'failed'
        if (data.findings_count !== undefined) {
          fcState.value.findingsCount = data.findings_count
        }
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
    // 保存 scanId 以便在 onclose 中使用
    const currentScanId = scanId

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

      quickScanWs.onclose = async () => {
        console.log('Quick scan WebSocket closed')
        // 如果扫描仍在进行但 WebSocket 关闭，尝试通过 API 获取最终结果
        if (isQuickScanning.value && !quickScanResult.value) {
          console.log('WebSocket closed while scanning, fetching result via API...')
          try {
            const result = await api.getScanResult(currentScanId)
            if (result.success && result.data) {
              const status = result.data.status
              if (status === 'completed') {
                quickScanResult.value = {
                  scan_id: currentScanId,
                  findings_count: (result.data.findings?.length || 0) + (result.data.vuln_findings?.length || 0),
                  target_path: result.data.target_path,
                }
                isQuickScanning.value = false
                quickScanProgress.value = null
              } else if (status === 'failed') {
                console.error('Scan failed:', result.data.error_message)
                isQuickScanning.value = false
                quickScanProgress.value = null
              }
              // 如果状态是其他值（如 pending/indexing/analyzing），保持扫描状态
            }
          } catch (e) {
            console.error('Failed to fetch scan result:', e)
          }
        }
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
      try {
        quickScanWs.__manualClose = true
        quickScanWs.onopen = null
        quickScanWs.onmessage = null
        quickScanWs.onerror = null
        quickScanWs.onclose = null
        quickScanWs.close(1000, 'Scan completed')
      } catch (e) {
        // ignore
      }
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
    // 取消会话列表请求
    if (sessionsAbortController) {
      sessionsAbortController.abort()
      sessionsAbortController = null
    }
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

    // LLM 调用过程 (实时展示)
    llmCallHistory,
    currentLlmCall,
    isLlmThinking,

    // 实时发现
    realtimeFindings,
    analysisProgress,

    // Function Calling 状态
    fcState,
    resetFCState,
    updateFCState,
    addFCToolCall,
    updateFCToolCallStatus,
    processFCToolCallMessage,
    generateToolCallId,

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
