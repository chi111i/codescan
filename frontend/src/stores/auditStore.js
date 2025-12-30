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

  // 标记是否为“主动关闭”（用于避免页面切换时触发自动重连）
  // 说明：浏览器 WebSocket 的 close 事件有时会返回非 1000（例如 1006），
  // 如果不区分主动关闭，会导致切页后仍在后台不断重连、解析消息，进而造成卡顿。
  // 这里通过给具体 ws 实例挂载 __manualClose 标记来避免竞态。

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

  // ============ LLM 调用过程状态 (实时展示) ============
  const llmCallHistory = ref([])  // LLM 调用历史 [{call_id, status, content_preview, tool_calls, ...}]
  const currentLlmCall = ref(null)  // 当前正在进行的 LLM 调用
  const isLlmThinking = ref(false)  // LLM 是否正在思考

  // ============ 实时发现状态 ============
  const realtimeFindings = ref([])  // 实时发现的漏洞列表
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
  const updateFCToolCallStatus = (toolName, status, output = null) => {
    const existing = fcState.value.toolCalls.find(
      tc => tc.toolName === toolName && tc.status === 'running'
    )
    if (existing) {
      existing.status = status
      if (output !== null) {
        existing.output = output
      }
    }
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
    chatMessages.value.push({
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
  // 修复：只在 WebSocket 完全关闭（CLOSED）时才重连，避免在 CLOSING 状态时创建新连接
  const ensureWebSocketConnected = () => {
    // 只有当没有 WebSocket 或者 WebSocket 已完全关闭时才重连
    // 不要在 CONNECTING 或 CLOSING 状态时干扰
    const shouldReconnect = currentSession.value && (!ws || ws.readyState === WebSocket.CLOSED)
    if (shouldReconnect) {
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
    if (wsReconnectTimer) {
      clearTimeout(wsReconnectTimer)
      wsReconnectTimer = null
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
      }

      wsInstance.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
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
    // 清除重连定时器
    if (wsReconnectTimer) {
      clearTimeout(wsReconnectTimer)
      wsReconnectTimer = null
    }
    wsReconnectAttempts = 0

    // 清除消息缓冲定时器（防止页面切换后仍尝试更新状态）
    if (messageBufferTimer) {
      clearTimeout(messageBufferTimer)
      messageBufferTimer = null
    }
    messageBuffer = ''

    // 关闭 WebSocket
    // 修复：不要立即将 ws 设为 null，保持 onclose 处理器以尊重 __manualClose 标记
    // 这可以防止竞态条件：在旧连接完全关闭前创建新连接
    if (ws) {
      try {
        ws.__manualClose = true
        // 只清除 onopen/onmessage/onerror，保留 onclose 让其自然触发
        // 这样 onclose 中的 __manualClose 检查才能正常工作
        ws.onopen = null
        ws.onmessage = null
        ws.onerror = null
        // 注意：不再设置 ws.onclose = null
        ws.close(1000, 'User disconnect')
        // 注意：不再设置 ws = null
        // WebSocket 会进入 CLOSING 状态，然后变成 CLOSED
        // ensureWebSocketConnected 已修复为只在 CLOSED 状态时重连
      } catch (e) {
        // ignore
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
        fcState.value.enabled = true
        fcState.value.status = 'analyzing'
        if (data.sink_symbol) {
          fcState.value.currentSink = data.sink_symbol
        }
        if (data.status === 'start') {
          addFCToolCall({
            id: `tc_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`,
            toolName: data.tool_name || 'unknown',
            status: 'running',
            input: data.tool_input || {},
            output: null,
            timestamp: data.timestamp || new Date().toISOString(),
          })
        } else if (data.status === 'end') {
          updateFCToolCallStatus(data.tool_name, 'completed', data.tool_output)
        }
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
