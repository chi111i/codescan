<template>
  <div class="h-[calc(100vh-3rem)] flex flex-col">
    <!-- 页面标题 + 模式切换 -->
    <div class="flex items-center justify-between mb-4 shrink-0">
      <div>
        <h1 class="text-3xl font-bold text-white mb-2 flex items-center gap-3">
          <span class="px-2 py-1 text-xs rounded bg-gradient-to-r from-violet-500 to-purple-500 text-white">NEW</span>
          智能审计
        </h1>
        <p class="text-white/60">AI 驱动的智能代码安全审计，支持自主工具调用</p>
      </div>

      <!-- 模式切换 Tab（仅在无会话时显示） -->
      <div v-if="!currentSession" class="flex items-center gap-2 bg-white/10 p-1 rounded-xl">
        <button
          @click="auditMode = 'conversation'"
          class="px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200"
          :class="auditMode === 'conversation'
            ? 'bg-white/90 text-violet-700 shadow-sm'
            : 'text-white/70 hover:text-white hover:bg-white/10'"
        >
          <span class="flex items-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/>
            </svg>
            对话审计
          </span>
        </button>
        <button
          @click="auditMode = 'quick-scan'"
          class="px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200"
          :class="auditMode === 'quick-scan'
            ? 'bg-white/90 text-violet-700 shadow-sm'
            : 'text-white/70 hover:text-white hover:bg-white/10'"
        >
          <span class="flex items-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
            </svg>
            快速扫描
          </span>
        </button>
      </div>
      <div class="flex items-center gap-3">
        <!-- 会话状态 -->
        <div v-if="currentSession" class="flex items-center gap-2 px-4 py-2 rounded-xl" :class="sessionStatusClass">
          <div class="w-2 h-2 rounded-full" :class="sessionStatusDotClass"></div>
          <span class="text-sm font-medium">{{ sessionStatusText }}</span>
        </div>
        <!-- 操作按钮 -->
        <button
          v-if="currentSession"
          @click="clearHistory"
          class="btn-secondary text-yellow-500 hover:bg-yellow-500/10"
          title="清空对话历史"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
          </svg>
        </button>
        <button
          v-if="currentSession"
          @click="deleteCurrentSession"
          class="btn-secondary text-red-500 hover:bg-red-500/10"
          title="删除会话"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </button>
      </div>
    </div>

    <!-- 无会话时：根据模式显示不同界面 -->
    <div v-if="!currentSession" class="flex-1 flex flex-col min-h-0">
      <!-- 快速扫描模式 - 两步扫描 -->
      <div v-if="auditMode === 'quick-scan'" class="flex-1 flex flex-col min-h-0">
        <!-- 阶段1：配置阶段 -->
        <div v-if="scanPhase === 'config'" class="flex-1 flex items-center justify-center">
          <div class="glass-card rounded-2xl p-8 max-w-2xl w-full">
            <div class="text-center mb-6">
              <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-blue-500 to-cyan-600 flex items-center justify-center shadow-lg shadow-blue-500/30">
                <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
              </div>
              <h2 class="text-2xl font-bold text-gray-800 mb-2">快速安全扫描</h2>
              <p class="text-gray-500">发现触发点 → 选择分析目标 → LLM 深度分析</p>
            </div>

            <!-- 扫描配置面板 -->
            <ScanConfigPanel
              :is-scanning="isLoadingSinkSites"
              @start-scan="discoverSinkSites"
            />
          </div>
        </div>

        <!-- 阶段2：发现中 -->
        <div v-else-if="scanPhase === 'discovering'" class="flex-1 flex items-center justify-center">
          <div class="glass-card rounded-2xl p-8 max-w-md w-full text-center">
            <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-blue-500/10 flex items-center justify-center">
              <svg class="w-8 h-8 text-blue-500 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            </div>
            <h3 class="text-lg font-semibold text-gray-800 mb-2">正在扫描触发点...</h3>
            <p class="text-gray-500 text-sm">正在分析代码，识别危险函数调用</p>
          </div>
        </div>

        <!-- 阶段3：选择触发点 -->
        <div v-else-if="scanPhase === 'selecting' || scanPhase === 'analyzing' || scanPhase === 'completed'" class="flex-1 grid grid-cols-12 gap-4 min-h-0">
          <!-- 左栏：触发点选择 + 调用图 -->
          <div class="col-span-8 flex flex-col gap-4 min-h-0 overflow-hidden">
            <!-- 返回按钮 -->
            <div class="shrink-0 flex items-center justify-between">
              <button
                @click="backToConfig"
                class="flex items-center gap-2 text-sm text-gray-600 hover:text-gray-800 transition-colors"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
                </svg>
                返回配置
              </button>
              <div class="flex items-center gap-2">
                <button
                  @click="showCallGraph = !showCallGraph"
                  class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm transition-all"
                  :class="showCallGraph ? 'bg-purple-500 text-white' : 'bg-white/50 text-gray-600 hover:bg-white/70'"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7"/>
                  </svg>
                  {{ showCallGraph ? '隐藏调用图' : '显示调用图' }}
                </button>
              </div>
            </div>

            <!-- 调用图可视化 -->
            <transition name="fade">
              <div v-if="showCallGraph && callGraphData" class="glass-card rounded-2xl overflow-hidden shrink-0" style="height: 300px;">
                <CallGraphViewer
                  :nodes="callGraphData.nodes || []"
                  :edges="callGraphData.edges || []"
                  :stats="callGraphData.stats || {}"
                  @node-click="(node) => console.log('Node clicked:', node)"
                  @view-chains="viewCallChains"
                />
              </div>
            </transition>

            <!-- 触发点选择组件 -->
            <div class="glass-card rounded-2xl flex-1 overflow-y-auto min-h-0">
              <SinkSiteSelector
                :sink-sites="sinkSites"
                :stats="sinkSitesStats"
                :analyzing="scanPhase === 'analyzing'"
                interaction-mode="two-step"
                @analyze="analyzeSelectedSinks"
                @update:selected="handleSinkSiteSelect"
                @view-chains="viewCallChains"
              />
            </div>
          </div>

          <!-- 右栏：LLM 交互面板 -->
          <div class="col-span-4 flex flex-col gap-4 min-h-0 overflow-hidden">
            <!-- FC 分析进度面板 -->
            <FCProgressPanel
              v-if="fcState.enabled"
              :current-sink="fcState.currentSink"
              :current-turn="fcState.currentTurn"
              :total-tool-calls="fcState.totalToolCalls"
              :tool-calls="fcState.toolCalls"
              :findings-count="fcState.findingsCount"
              :status="fcState.status"
            />

            <!-- LLM 交互面板 -->
            <LLMInteractionPanel
              v-if="interactions.length > 0 || streamingContent"
              :interactions="interactions"
              :streaming-content="streamingContent"
              :full-height="true"
              @clear="clearInteractions"
            />

            <!-- 分析状态卡片 -->
            <div v-if="currentScan" class="glass-card rounded-2xl p-4 shrink-0">
              <div class="flex items-center justify-between mb-3">
                <span class="text-sm font-medium text-gray-700">分析状态</span>
                <span
                  class="px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="{
                    'bg-blue-100 text-blue-700': scanPhase === 'analyzing',
                    'bg-green-100 text-green-700': scanPhase === 'completed',
                    'bg-yellow-100 text-yellow-700': scanPhase === 'selecting',
                  }"
                >
                  {{ scanPhase === 'analyzing' ? '分析中' : scanPhase === 'completed' ? '已完成' : '待分析' }}
                </span>
              </div>
              <div class="space-y-2 text-sm text-gray-600">
                <div class="flex justify-between">
                  <span>触发点</span>
                  <span class="font-medium">{{ sinkSites.length }} 个</span>
                </div>
                <div class="flex justify-between">
                  <span>已选择</span>
                  <span class="font-medium text-blue-600">{{ selectedSinkIds.length }} 个</span>
                </div>
                <div v-if="currentScan.findings" class="flex justify-between">
                  <span>发现问题</span>
                  <span class="font-medium text-orange-600">{{ currentScan.findings.length }} 个</span>
                </div>
              </div>
              <!-- 查看结果按钮 -->
              <button
                v-if="scanPhase === 'completed' && currentScan.scan_id"
                @click="openResultsModal(currentScan.scan_id)"
                class="w-full mt-4 btn-primary text-sm"
              >
                查看完整报告
              </button>
            </div>

            <!-- 空状态提示 -->
            <div v-if="!fcState.enabled && interactions.length === 0" class="glass-card rounded-2xl p-6 flex-1 flex items-center justify-center">
              <div class="text-center text-gray-400">
                <svg class="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
                </svg>
                <p class="text-sm">选择触发点后点击"开始分析"</p>
                <p class="text-xs mt-1">LLM 分析过程将在此显示</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 对话审计模式（原有界面） -->
      <div v-else class="flex-1 flex items-center justify-center">
        <div class="glass-card rounded-2xl p-8 max-w-xl w-full">
          <div class="text-center mb-8">
            <div class="w-20 h-20 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center shadow-lg shadow-violet-500/30">
              <svg class="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
              </svg>
            </div>
            <h2 class="text-2xl font-bold text-gray-800 mb-2">创建智能审计会话</h2>
            <p class="text-gray-500">AI 智能体将自主调用工具进行深度代码分析</p>
          </div>

        <form @submit.prevent="createSession" class="space-y-6">
          <!-- 目标路径 -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">目标代码路径</label>
            <input
              v-model="newSessionConfig.targetPath"
              type="text"
              class="input-glass w-full"
              placeholder="例如: /path/to/your/project"
              required
            />
          </div>

          <!-- 语言选择 -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-3">扫描语言（可选）</label>
            <div class="flex flex-wrap gap-2">
              <label
                v-for="lang in availableLanguages"
                :key="lang.value"
                class="lang-chip"
                :class="{ active: newSessionConfig.languages.includes(lang.value) }"
              >
                <input
                  type="checkbox"
                  :value="lang.value"
                  v-model="newSessionConfig.languages"
                  class="hidden"
                />
                <span class="lang-icon" :class="lang.iconClass">{{ lang.icon }}</span>
                <span>{{ lang.label }}</span>
              </label>
            </div>
          </div>

          <!-- 高级选项 -->
          <div class="space-y-4">
            <label class="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" v-model="newSessionConfig.enableCallChain" class="rounded" />
              <span class="text-sm text-gray-700">启用调用链分析工具</span>
            </label>
            <label class="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" v-model="newSessionConfig.enableVariantAnalysis" class="rounded" />
              <span class="text-sm text-gray-700">启用变体分析工具</span>
            </label>
          </div>

          <!-- 提交按钮 -->
          <button
            type="submit"
            class="btn-primary w-full flex items-center justify-center gap-2"
            :disabled="isCreatingSession || !newSessionConfig.targetPath"
          >
            <svg v-if="isCreatingSession" class="w-5 h-5 spinner" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>{{ isCreatingSession ? '正在初始化智能体...' : '开始智能审计' }}</span>
          </button>
        </form>

        <!-- 已有会话列表 -->
        <div v-if="existingSessions.length > 0" class="mt-8 pt-6 border-t border-gray-200/50">
          <h3 class="text-sm font-medium text-gray-700 mb-3">已有会话</h3>
          <div class="space-y-2 max-h-48 overflow-y-auto">
            <div
              v-for="session in existingSessions"
              :key="session.session_id"
              class="flex items-center justify-between p-3 rounded-xl bg-white/30 hover:bg-white/50 cursor-pointer transition-all"
              @click="loadSession(session.session_id)"
            >
              <div>
                <div class="font-medium text-gray-800 text-sm">{{ session.target_path }}</div>
                <div class="text-xs text-gray-500">
                  {{ session.messages_count || 0 }} 条对话 ·
                  {{ session.tool_calls_count || 0 }} 次工具调用 ·
                  {{ formatDate(session.created_at) }}
                </div>
              </div>
              <div class="flex items-center gap-2">
                <span class="px-2 py-1 rounded-full text-xs" :class="getSessionBadgeClass(session.status)">
                  {{ getSessionStatusText(session.status) }}
                </span>
                <button
                  @click.stop="deleteSession(session.session_id)"
                  class="p-1 rounded hover:bg-red-100 text-gray-400 hover:text-red-500"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    </div>

    <!-- 有会话时：显示聊天界面 -->
    <div v-else class="flex-1 grid grid-cols-12 gap-4 min-h-0">
      <!-- 左栏：工具面板 -->
      <div class="col-span-3 glass-card rounded-2xl p-4 flex flex-col min-h-0 overflow-hidden">
        <div class="flex items-center justify-between mb-4 shrink-0">
          <h3 class="font-semibold text-gray-800 flex items-center gap-2">
            <svg class="w-5 h-5 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/>
            </svg>
            可用工具
          </h3>
          <span class="text-xs text-gray-500">{{ availableTools.length }} 个</span>
        </div>

        <!-- 工具列表 -->
        <div class="flex-1 overflow-y-auto space-y-2 dark-scroll">
          <div
            v-for="tool in availableTools"
            :key="tool.name"
            class="p-3 rounded-xl bg-white/30 hover:bg-white/50 transition-all cursor-pointer"
            @click="showToolDetail(tool)"
          >
            <div class="flex items-center gap-2">
              <div class="w-8 h-8 rounded-lg flex items-center justify-center text-white text-xs" :class="getToolCategoryColor(tool.category)">
                {{ tool.name.substring(0, 2).toUpperCase() }}
              </div>
              <div class="flex-1 min-w-0">
                <div class="font-medium text-gray-800 text-sm truncate">{{ tool.name }}</div>
                <div class="text-xs text-gray-500 truncate">{{ tool.description }}</div>
              </div>
            </div>
          </div>

          <div v-if="availableTools.length === 0" class="text-center py-8 text-gray-400 text-sm">
            正在加载工具列表...
          </div>
        </div>

        <!-- 工具调用历史 -->
        <div class="mt-4 pt-4 border-t border-gray-200/50 shrink-0">
          <div class="flex items-center justify-between mb-2">
            <span class="text-xs font-medium text-gray-600">工具调用记录</span>
            <span class="text-xs text-gray-400">{{ toolCallHistory.length }} 次</span>
          </div>
          <div class="space-y-1 max-h-32 overflow-y-auto dark-scroll">
            <div
              v-for="(call, index) in toolCallHistory.slice(-5).reverse()"
              :key="index"
              class="text-xs p-2 rounded-lg"
              :class="call.status === 'success' ? 'bg-green-50' : call.status === 'failed' ? 'bg-red-50' : 'bg-yellow-50'"
            >
              <div class="flex items-center justify-between">
                <span class="font-medium text-gray-700">{{ call.tool_name }}</span>
                <span class="text-gray-400">{{ call.duration_ms }}ms</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 中栏：主对话区域 -->
      <div class="col-span-6 glass-card rounded-2xl p-4 flex flex-col min-h-0 overflow-hidden">
        <div class="flex items-center justify-between mb-4 shrink-0">
          <h3 class="font-semibold text-gray-800 flex items-center gap-2">
            <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/>
            </svg>
            智能对话
          </h3>
          <div class="flex items-center gap-2 text-xs text-gray-500">
            <span>LLM 调用: {{ sessionStats.total_llm_calls || 0 }}</span>
            <span>·</span>
            <span>Token: {{ formatNumber(sessionStats.total_tokens_used || 0) }}</span>
          </div>
        </div>

        <!-- 对话历史 -->
        <div ref="chatContainer" class="flex-1 overflow-y-auto space-y-4 dark-scroll mb-4">
          <div
            v-for="(msg, index) in chatMessages"
            :key="index"
            v-memo="[msg.role, msg.content, msg.tool_calls && msg.tool_calls.length]"
            class="chat-message"
            :class="msg.role"
          >
            <div class="message-header">
              <span class="message-role">{{ msg.role === 'user' ? '你' : 'AI 智能体' }}</span>
              <span class="message-time">{{ formatTime(msg.timestamp) }}</span>
            </div>
            <div class="message-content" v-html="renderMarkdown(msg.content)"></div>

            <!-- 工具调用详情 -->
            <div v-if="msg.tool_calls && msg.tool_calls.length > 0" class="mt-3 space-y-2">
              <div class="text-xs text-gray-500 mb-1">工具调用:</div>
              <div
                v-for="tc in msg.tool_calls"
                :key="tc.id"
                class="tool-call-card p-2 rounded-lg text-xs"
                :class="tc.status === 'success' ? 'bg-green-50 border-green-200' : tc.status === 'failed' ? 'bg-red-50 border-red-200' : 'bg-yellow-50 border-yellow-200'"
              >
                <div class="flex items-center justify-between">
                  <span class="font-medium text-gray-700">{{ tc.tool_name }}</span>
                  <span class="text-gray-400">{{ tc.duration_ms }}ms</span>
                </div>
                <details v-if="tc.result" class="mt-1">
                  <summary class="text-gray-500 cursor-pointer hover:text-gray-700">查看结果</summary>
                  <pre class="mt-1 p-2 bg-white/50 rounded text-xs overflow-x-auto">{{ JSON.stringify(tc.result, null, 2).substring(0, 500) }}</pre>
                </details>
              </div>
            </div>
          </div>

          <!-- 处理中提示 -->
          <div v-if="isProcessing" class="flex items-center gap-3 p-4 rounded-xl bg-violet-50">
            <div class="w-8 h-8 rounded-full bg-violet-500 flex items-center justify-center">
              <svg class="w-5 h-5 text-white spinner" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            </div>
            <div>
              <div class="font-medium text-violet-700">AI 智能体正在处理...</div>
              <div class="text-sm text-violet-500">{{ currentProcessingStep }}</div>
            </div>
          </div>

          <!-- 空状态 -->
          <div v-if="chatMessages.length === 0 && !isProcessing" class="flex flex-col items-center justify-center h-full text-gray-400">
            <svg class="w-20 h-20 mb-4 text-violet-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
            </svg>
            <p class="text-center text-lg font-medium text-gray-500 mb-2">
              开始与 AI 智能体对话
            </p>
            <p class="text-center text-sm max-w-md">
              描述你想要分析的安全问题，智能体会自动选择并调用适合的工具进行深度分析。
            </p>
            <div class="mt-6 flex flex-wrap gap-2 justify-center">
              <button
                v-for="suggestion in quickSuggestions"
                :key="suggestion"
                @click="sendQuickMessage(suggestion)"
                class="px-3 py-1.5 rounded-lg text-sm bg-white/50 text-gray-600 hover:bg-white/70 transition-all"
              >
                {{ suggestion }}
              </button>
            </div>
          </div>
        </div>

        <!-- 输入区域 -->
        <div class="shrink-0 space-y-3">
          <div class="flex gap-2">
            <input
              v-model="chatInput"
              type="text"
              class="input-glass flex-1"
              placeholder="输入你的问题或分析指令..."
              @keyup.enter="sendMessage"
              :disabled="isProcessing"
            />
            <button
              @click="sendMessage"
              :disabled="!chatInput.trim() || isProcessing"
              class="btn-primary px-6"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"/>
              </svg>
            </button>
          </div>
        </div>
      </div>

      <!-- 右栏：LLM 过程 + 实时发现 -->
      <div class="col-span-3 flex flex-col gap-4 min-h-0 overflow-hidden">
        <!-- 分析进度 -->
        <AnalysisProgressBar v-if="analysisProgress" :progress="analysisProgress" class="shrink-0" />

        <!-- LLM 调用过程面板 -->
        <div class="glass-card rounded-2xl p-4 flex flex-col min-h-0 overflow-hidden" style="flex: 1 1 45%;">
          <div class="flex items-center justify-between mb-3 shrink-0">
            <h4 class="font-semibold text-gray-800 flex items-center gap-2 text-sm">
              <svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
              </svg>
              LLM 调用过程
            </h4>
            <span class="text-xs text-gray-400">{{ llmCallHistory.length }} 次</span>
          </div>

          <!-- 当前 LLM 调用 (思考中) -->
          <LLMCallCard
            v-if="currentLlmCall && isLlmThinking"
            :call="currentLlmCall"
            :is-new="true"
            class="mb-2 shrink-0"
          />

          <!-- LLM 调用历史 -->
          <div class="flex-1 overflow-y-auto space-y-2 dark-scroll">
            <LLMCallCard
              v-for="(call, index) in llmCallHistory.slice().reverse().slice(0, 10)"
              :key="call.call_id || index"
              :call="call"
            />
            <div v-if="llmCallHistory.length === 0 && !currentLlmCall" class="text-center py-6 text-gray-400 text-sm">
              等待 LLM 调用...
            </div>
          </div>
        </div>

        <!-- 实时发现面板 -->
        <div class="glass-card rounded-2xl p-4 flex flex-col min-h-0 overflow-hidden" style="flex: 1 1 55%;">
          <div class="flex items-center justify-between mb-3 shrink-0">
            <h4 class="font-semibold text-gray-800 flex items-center gap-2 text-sm">
              <svg class="w-4 h-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
              </svg>
              实时发现
            </h4>
            <span class="text-xs px-2 py-0.5 rounded-full" :class="realtimeFindings.length > 0 ? 'bg-red-100 text-red-700' : 'text-gray-400'">
              {{ realtimeFindings.length }} 个
            </span>
          </div>

          <!-- 发现列表 -->
          <div class="flex-1 overflow-y-auto space-y-2 dark-scroll">
            <FindingCard
              v-for="finding in realtimeFindings.slice(0, 20)"
              :key="finding.id"
              :finding="finding"
            />
            <div v-if="realtimeFindings.length === 0" class="text-center py-6 text-gray-400 text-sm">
              <svg class="w-10 h-10 mx-auto mb-2 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              暂无发现
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- 调用链选择器模态框 -->
  <transition name="fade">
    <div
      v-if="showChainSelector"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
      @click.self="closeChainSelector"
    >
      <div class="w-full max-w-4xl max-h-[80vh] bg-white/95 backdrop-blur-xl rounded-2xl shadow-2xl overflow-hidden">
        <div class="flex items-center justify-between p-6 border-b border-gray-200/50">
          <div>
            <h3 class="text-lg font-semibold text-gray-800">调用链详情</h3>
            <p v-if="currentSinkForChains" class="text-sm text-gray-500 mt-1">
              触发点: {{ currentSinkForChains.symbol || currentSinkForChains.name }}
            </p>
          </div>
          <button
            class="p-2 rounded-lg hover:bg-gray-100 transition-colors"
            @click="closeChainSelector"
          >
            <svg class="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>
        <div class="p-6 overflow-y-auto max-h-[calc(80vh-140px)]">
          <div v-if="isLoadingChains" class="flex items-center justify-center py-12">
            <div class="flex items-center gap-3 text-gray-500">
              <svg class="w-6 h-6 spinner" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              <span>加载调用链中...</span>
            </div>
          </div>
          <CallChainSelector
            v-else
            :chains="callChains"
            :sink-id="currentSinkForChains?.id || ''"
            :sink-symbol="currentSinkForChains?.symbol || currentSinkForChains?.name || ''"
            @confirm="confirmChainSelection"
            @cancel="closeChainSelector"
            @update:selected="(ids) => selectedChainIds = ids"
          />
        </div>
        <div class="flex justify-end gap-3 p-4 border-t border-gray-200/50 bg-gray-50/50">
          <button
            type="button"
            class="btn-secondary"
            @click="closeChainSelector"
          >
            关闭
          </button>
          <button
            v-if="selectedChainIds.length > 0"
            type="button"
            class="btn-primary flex items-center gap-2"
            @click="closeChainSelector"
          >
            <span>确认选择 ({{ selectedChainIds.length }})</span>
          </button>
        </div>
      </div>
    </div>
  </transition>

  <!-- 扫描结果弹窗 -->
  <ScanResultsModal
    v-model:visible="showResultsModal"
    :scan-id="resultsScanId"
    @close="showResultsModal = false"
  />
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { useRoute, useRouter, onBeforeRouteLeave } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useAuditStore } from '../stores/auditStore'
import * as api from '../api'
import ScanConfigPanel from '../components/ScanConfigPanel.vue'
import LLMCallCard from '../components/LLMCallCard.vue'
import FindingCard from '../components/FindingCard.vue'
import AnalysisProgressBar from '../components/AnalysisProgressBar.vue'
import ScanResultsModal from '../components/ScanResultsModal.vue'
// 两步扫描模式组件
import SinkSiteSelector from '../components/SinkSiteSelector.vue'
import CallChainSelector from '../components/CallChainSelector.vue'
import CallGraphViewer from '../components/CallGraphViewer.vue'
import LLMInteractionPanel from '../components/LLMInteractionPanel.vue'
import FCProgressPanel from '../components/FCProgressPanel.vue'

const route = useRoute()
const router = useRouter()
const auditStore = useAuditStore()

// ============ 从 store 解构响应式状态 ============
const {
  currentSession,
  existingSessions,
  isCreatingSession,
  chatMessages,
  isProcessing,
  currentProcessingStep,
  availableTools,
  toolCallHistory,
  sessionStats,
  sessionStatusClass,
  sessionStatusDotClass,
  sessionStatusText,
  isQuickScanning,
  quickScanProgress,
  quickScanResult,
  // LLM 调用过程状态
  llmCallHistory,
  currentLlmCall,
  isLlmThinking,
  // 实时发现状态
  realtimeFindings,
  analysisProgress,
} = storeToRefs(auditStore)

// ============ 本地状态 ============

// 审计模式
const auditMode = ref('conversation') // 'conversation' | 'quick-scan'

// 扫描结果弹窗状态
const showResultsModal = ref(false)
const resultsScanId = ref('')

// 新会话配置
const newSessionConfig = reactive({
  targetPath: '',
  languages: [],
  enableCallChain: true,
  enableVariantAnalysis: true,
})

// 对话输入
const chatInput = ref('')
const chatContainer = ref(null)

// ============ 两步扫描模式状态 ============
// 扫描阶段: 'config' | 'discovering' | 'selecting' | 'analyzing' | 'completed'
const scanPhase = ref('config')
const sinkSites = ref([])  // 发现的触发点列表
const sinkSitesStats = ref(null)  // 触发点统计信息
const selectedSinkIds = ref([])  // 用户选中的触发点 ID
const callChains = ref([])  // 当前触发点的调用链列表
const currentSinkForChains = ref(null)  // 正在查看调用链的触发点
const selectedChainIds = ref([])  // 用户选中的调用链 ID
const isLoadingSinkSites = ref(false)  // 加载触发点中
const isLoadingChains = ref(false)  // 加载调用链中
const showChainSelector = ref(false)  // 是否显示调用链选择器
const callGraphData = ref(null)  // 调用图数据
const showCallGraph = ref(false)  // 是否显示调用图
const interactions = ref([])  // LLM 交互日志
const streamingContent = ref('')  // LLM 流式输出
const currentScan = ref(null)  // 当前扫描任务
let scanWs = null  // 扫描 WebSocket

// 扫描配置（用于两步扫描模式）
const scanConfig = reactive({
  targetPath: '',
  languages: [],
  vulnTypes: ['rce', 'command_injection', 'sql_injection'],
  maxChainDepth: 5,
  useChainAnalysis: true,
})

// FC (Function Calling) 状态
const fcState = reactive({
  enabled: false,
  currentSink: '',
  currentTurn: 0,
  totalToolCalls: 0,
  toolCalls: [],
  findingsCount: 0,
  status: 'idle', // idle, analyzing, completed, failed
})

// ============ 计算属性 ============

const availableLanguages = [
  { value: 'python', label: 'Python', icon: 'Py', iconClass: 'bg-blue-500' },
  { value: 'javascript', label: 'JavaScript', icon: 'JS', iconClass: 'bg-yellow-500' },
  { value: 'typescript', label: 'TypeScript', icon: 'TS', iconClass: 'bg-blue-600' },
  { value: 'php', label: 'PHP', icon: 'PHP', iconClass: 'bg-purple-500' },
  { value: 'java', label: 'Java', icon: 'JV', iconClass: 'bg-orange-500' },
  { value: 'go', label: 'Go', icon: 'GO', iconClass: 'bg-cyan-500' },
]

const quickSuggestions = [
  '分析这个项目的安全风险',
  '查找 SQL 注入漏洞',
  '检查权限控制是否完善',
  '查找危险函数调用',
  '分析认证逻辑是否安全',
]

// ============ 方法 ============

// 会话管理
const fetchExistingSessions = () => auditStore.fetchExistingSessions()

const createSession = async () => {
  if (!newSessionConfig.targetPath) return

  try {
    await auditStore.createSession(newSessionConfig)
  } catch (error) {
    alert('创建会话失败: ' + (error.response?.data?.detail || error.message))
  }
}

const loadSession = async (sessionId) => {
  try {
    await auditStore.loadSession(sessionId)
  } catch (error) {
    alert('加载会话失败')
  }
}

// 从 URL 参数恢复会话
const restoreFromUrl = async () => {
  const sessionId = route.query.session
  if (sessionId) {
    try {
      await auditStore.restoreSession(sessionId)
      router.replace({ path: '/audit' })
    } catch (error) {
      console.error('从 URL 恢复会话失败:', error)
    }
  }
}

const deleteSession = async (sessionId) => {
  if (!confirm('确定要删除该会话吗？')) return

  try {
    await auditStore.deleteSession(sessionId)
  } catch (error) {
    console.error('删除会话失败:', error)
  }
}

const deleteCurrentSession = () => {
  if (currentSession.value) {
    deleteSession(currentSession.value.session_id)
  }
}

const clearHistory = async () => {
  if (!currentSession.value || !confirm('确定要清空对话历史吗？')) return

  try {
    await auditStore.clearHistory()
  } catch (error) {
    console.error('清空历史失败:', error)
  }
}

// ============ 快速扫描功能 ============

const handleQuickScan = async (config) => {
  try {
    await auditStore.startQuickScan(config)
  } catch (error) {
    alert('启动扫描失败: ' + (error.response?.data?.detail || error.message))
  }
}

const continueInConversation = async () => {
  if (!quickScanResult.value) return

  auditMode.value = 'conversation'
  newSessionConfig.targetPath = quickScanResult.value.target_path || ''
  auditStore.clearQuickScanResult()
}

// 打开扫描结果弹窗
const openResultsModal = (scanId) => {
  if (!scanId) return
  resultsScanId.value = scanId
  showResultsModal.value = true
}

// ============ 两步扫描模式功能 ============

// 加载调用图数据
const loadCallGraphData = async (targetPath) => {
  if (!targetPath) return

  try {
    console.log('开始加载调用图数据...')
    const result = await api.analyzeCallGraph({
      target_path: targetPath,
      languages: scanConfig.languages.length > 0 ? scanConfig.languages : null,
    })

    if (result.success && result.data) {
      callGraphData.value = {
        nodes: result.data.nodes || [],
        edges: result.data.edges || [],
        stats: result.data.stats || {},
      }
      console.log(`调用图加载完成: ${callGraphData.value.nodes.length} 节点, ${callGraphData.value.edges.length} 边`)
    } else {
      console.warn('调用图数据为空')
      callGraphData.value = null
    }
  } catch (error) {
    console.error('加载调用图失败:', error)
    callGraphData.value = null
  }
}

// 第一步：发现触发点（不进行 LLM 分析）
const discoverSinkSites = async (config) => {
  // 从 ScanConfigPanel 接收配置
  scanConfig.targetPath = config.target_path
  scanConfig.languages = config.languages || []
  scanConfig.vulnTypes = config.vuln_types || ['rce', 'command_injection', 'sql_injection']

  if (!scanConfig.targetPath) {
    alert('请输入目标路径')
    return
  }

  scanPhase.value = 'discovering'
  isLoadingSinkSites.value = true
  sinkSites.value = []
  sinkSitesStats.value = null
  selectedSinkIds.value = []
  interactions.value = []

  try {
    const result = await api.scanSinkSites({
      target_path: scanConfig.targetPath,
      languages: scanConfig.languages.length > 0 ? scanConfig.languages : null,
      vuln_types: scanConfig.vulnTypes.length > 0 ? scanConfig.vulnTypes : null,
    })

    if (result.success && result.data) {
      const total = result.data.total || 0
      sinkSites.value = result.data.sink_sites || []
      sinkSitesStats.value = result.data.stats || null

      // 生成临时 scan_id 用于后续选择分析
      const tempScanId = `temp-${Date.now()}`
      currentScan.value = {
        scan_id: tempScanId,
        target_path: scanConfig.targetPath,
        status: 'sink_discovered',
        progress: 0.5,
        current_step: '等待用户选择触发点',
        findings: [],
      }

      scanPhase.value = 'selecting'
      console.log(`发现 ${total} 个触发点`)

      // 异步加载调用图数据（不阻塞主流程）
      loadCallGraphData(scanConfig.targetPath)
    } else {
      throw new Error(result.error || '扫描失败')
    }
  } catch (error) {
    console.error('发现触发点失败:', error)
    alert('扫描触发点失败: ' + error.message)
    scanPhase.value = 'config'
  } finally {
    isLoadingSinkSites.value = false
  }
}

// 处理触发点选择变化
const handleSinkSiteSelect = (ids) => {
  selectedSinkIds.value = ids
}

// 查看触发点的调用链
const viewCallChains = async (siteId) => {
  if (!currentScan.value) return

  const site = sinkSites.value.find(s => s.id === siteId)
  if (!site) return

  currentSinkForChains.value = site
  showChainSelector.value = true
  isLoadingChains.value = true
  callChains.value = []
  selectedChainIds.value = []

  try {
    const result = await api.getSinkCallChains(currentScan.value.scan_id, siteId, {
      max_depth: scanConfig.maxChainDepth,
      target_path: currentScan.value.target_path,  // 传入目标路径，支持临时 scan_id
    })
    if (result.success && result.data) {
      callChains.value = result.data.chains || []
    }
  } catch (error) {
    console.error('加载调用链失败:', error)
  } finally {
    isLoadingChains.value = false
  }
}

// 关闭调用链选择器
const closeChainSelector = () => {
  showChainSelector.value = false
  currentSinkForChains.value = null
  callChains.value = []
  selectedChainIds.value = []
}

// 确认选择的调用链
const confirmChainSelection = (chainIds) => {
  selectedChainIds.value = chainIds
  closeChainSelector()
}

// 第二步：对选中的触发点进行 LLM 分析
const analyzeSelectedSinks = async (sinkIds) => {
  if (!currentScan.value || sinkIds.length === 0) {
    alert('请先选择要分析的触发点')
    return
  }

  scanPhase.value = 'analyzing'
  resetFCState()
  interactions.value = []

  try {
    // 更新扫描状态
    currentScan.value.status = 'analyzing'
    currentScan.value.current_step = '正在进行 LLM 深度分析...'

    // 调用后端 API 创建分析任务
    const result = await api.analyzeSelectedSinks({
      target_path: currentScan.value.target_path || scanConfig.targetPath,
      sink_site_ids: sinkIds,
      use_chain_analysis: scanConfig.useChainAnalysis !== false,
      max_chain_depth: scanConfig.maxChainDepth || 5,
      use_function_calling: true,
      languages: scanConfig.languages.length > 0 ? scanConfig.languages : null,
    })

    if (result.success && result.data && result.data.scan_id) {
      const realScanId = result.data.scan_id
      currentScan.value.scan_id = realScanId

      // 连接 WebSocket 以接收实时进度
      try {
        scanWs = api.createScanWebSocket(realScanId)
        scanWs.onmessage = handleWebSocketMessage
        scanWs.onerror = () => {
          console.warn('WebSocket 连接失败')
        }
      } catch (e) {
        console.error('WebSocket 连接失败:', e)
      }
    }
  } catch (error) {
    console.error('分析失败:', error)
    alert('启动分析失败: ' + error.message)
    scanPhase.value = 'selecting'
  }
}

// WebSocket 消息处理
const handleWebSocketMessage = (event) => {
  const data = JSON.parse(event.data)
  if (data.type === 'progress') {
    currentScan.value = { ...currentScan.value, ...data }
    if (data.status === 'completed') {
      currentScan.value.progress = 1.0
      scanPhase.value = 'completed'
      fcState.status = 'completed'
    } else if (data.status === 'failed') {
      fcState.status = 'failed'
    }
  } else if (data.type === 'interaction') {
    handleInteraction(data.data)
  } else if (data.type === 'llm_stream') {
    if (data.content) {
      if (data.is_final) {
        streamingContent.value = ''
      } else {
        streamingContent.value += data.content
      }
    }
  } else if (data.type === 'fc_tool_call') {
    handleFCToolCall(data)
  } else if (data.type === 'fc_progress') {
    handleFCProgress(data)
  } else if (data.type === 'fc_finding') {
    handleFCFinding(data)
  } else if (data.type === 'fc_llm_thinking') {
    handleFCLLMThinking(data)
  } else if (data.type === 'new_finding') {
    if (currentScan.value && data.finding) {
      if (!currentScan.value.findings) {
        currentScan.value.findings = []
      }
      currentScan.value.findings.push(data.finding)
    }
  }
}

// LLM 交互处理
const handleInteraction = (interaction) => {
  interactions.value.push(interaction)
  if (interactions.value.length > 50) {
    interactions.value.shift()
  }
}

// FC 事件处理
const handleFCToolCall = (data) => {
  auditStore.processFCToolCallMessage(data, fcState)
}

const handleFCProgress = (data) => {
  fcState.enabled = true
  fcState.currentSink = data.sink_symbol || fcState.currentSink
  fcState.currentTurn = data.current_turn || fcState.currentTurn
  fcState.totalToolCalls = data.total_tool_calls || fcState.totalToolCalls
  fcState.status = data.status || 'analyzing'

  if (data.tool_calls && Array.isArray(data.tool_calls)) {
    fcState.toolCalls = data.tool_calls.map(tc => ({
      id: tc.id || auditStore.generateToolCallId(),
      tool_name: tc.tool_name || tc.name || 'unknown',
      arguments: tc.arguments || {},
      result: tc.result,
      error: tc.error,
      duration_ms: tc.duration_ms,
      status: tc.status || 'success',
      timestamp: data.timestamp,
    }))
  }
}

const handleFCFinding = (data) => {
  fcState.findingsCount += 1
}

const handleFCLLMThinking = (data) => {
  fcState.enabled = true
  fcState.status = 'analyzing'
  if (data.sink_symbol) {
    fcState.currentSink = data.sink_symbol
  }
}

const resetFCState = () => {
  fcState.enabled = false
  fcState.currentSink = ''
  fcState.currentTurn = 0
  fcState.totalToolCalls = 0
  fcState.toolCalls = []
  fcState.findingsCount = 0
  fcState.status = 'idle'
}

// 清空交互记录
const clearInteractions = () => {
  interactions.value = []
  streamingContent.value = ''
}

// 返回配置阶段
const backToConfig = () => {
  if (scanWs) {
    scanWs.close()
    scanWs = null
  }
  scanPhase.value = 'config'
  sinkSites.value = []
  sinkSitesStats.value = null
  selectedSinkIds.value = []
  currentScan.value = null
  resetFCState()
  clearInteractions()
}

// 对话交互
const sendMessage = async () => {
  if (!chatInput.value.trim() || !currentSession.value || isProcessing.value) return

  const message = chatInput.value.trim()
  chatInput.value = ''

  try {
    await auditStore.sendMessage(message)
    scrollToBottom()
  } catch (error) {
    // 错误已在 store 中处理
  }
}

const sendQuickMessage = (message) => {
  chatInput.value = message
  sendMessage()
}

// 工具相关
const showToolDetail = (tool) => {
  console.log('Tool detail:', tool)
}

const getToolCategoryColor = (category) => {
  const colors = {
    code_navigation: 'bg-blue-500',
    security_analysis: 'bg-red-500',
    call_chain: 'bg-purple-500',
    variant_analysis: 'bg-orange-500',
    general: 'bg-gray-500',
  }
  return colors[category] || 'bg-gray-500'
}

// 工具函数
const scrollToBottom = () => {
  nextTick(() => {
    if (chatContainer.value) {
      // 使用 requestAnimationFrame 优化滚动性能，避免布局抖动
      requestAnimationFrame(() => {
        chatContainer.value.scrollTop = chatContainer.value.scrollHeight
      })
    }
  })
}

const formatDate = (dateStr) => {
  if (!dateStr) return ''
  const date = new Date(dateStr)
  return date.toLocaleDateString('zh-CN', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

const formatTime = (date) => {
  if (!date) return ''
  if (typeof date === 'string') date = new Date(date)
  return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
}

const formatNumber = (num) => {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}

// 简易 markdown 渲染（性能优化 + 安全处理）
// - v-html 必须先做基础 HTML 转义，避免把 LLM 输出当作 HTML 注入页面
// - 使用小型缓存，避免在流式输出/高频更新时反复做同样的正则替换
const MD_CACHE_MAX = 200
const markdownCache = new Map()

const escapeHtml = (str) => {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

const renderMarkdown = (text) => {
  if (!text) return ''

  const key = String(text)
  const cached = markdownCache.get(key)
  if (cached) return cached

  const safeText = escapeHtml(key)
  const html = safeText
    .replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre class="bg-gray-900 text-gray-100 p-3 rounded-lg overflow-x-auto text-xs my-2"><code>$2</code></pre>')
    .replace(/`([^`]+)`/g, '<code class="bg-gray-100 px-1 rounded text-sm">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br>')

  markdownCache.set(key, html)
  if (markdownCache.size > MD_CACHE_MAX) {
    markdownCache.clear()
  }
  return html
}

const getSessionBadgeClass = (status) => {
  const classes = {
    ready: 'bg-green-100 text-green-700',
    processing: 'bg-blue-100 text-blue-700',
    idle: 'bg-gray-100 text-gray-600',
    error: 'bg-red-100 text-red-700',
  }
  return classes[status] || 'bg-gray-100 text-gray-600'
}

const getSessionStatusText = (status) => {
  const texts = {
    initializing: '初始化中',
    ready: '就绪',
    processing: '处理中',
    idle: '空闲',
    error: '错误',
  }
  return texts[status] || status
}

// ============ 生命周期 ============

onMounted(async () => {
  // 先检查 URL 参数，恢复历史会话
  await restoreFromUrl()
  // 加载会话列表
  fetchExistingSessions()
  // 如果已有会话，确保 WebSocket 连接正常
  auditStore.ensureWebSocketConnected()
})

// 统一资源清理：切页时关闭 WebSocket/取消请求，避免后台持续重连/解析消息导致卡顿
const cleanupResources = () => {
  try {
    // 清理本地扫描 WebSocket（使用与 auditStore 一致的标记模式）
    if (scanWs) {
      try {
        scanWs.__manualClose = true
        scanWs.onopen = null
        scanWs.onmessage = null
        scanWs.onerror = null
        scanWs.onclose = null
        scanWs.close(1000, 'Component cleanup')
      } catch (e) {
        // ignore
      }
      scanWs = null
    }
    // 清理 store 资源
    auditStore.cleanup()
  } catch (e) {
    // ignore
  }
}

// 路由离开前立即清理（比 onUnmounted 更早，配合 transition 可显著降低“切页卡死”概率）
onBeforeRouteLeave(() => {
  cleanupResources()
})

onUnmounted(() => {
  cleanupResources()
})

watch(chatMessages, () => {
  scrollToBottom()
}, { deep: true })
</script>

<style scoped>
.lang-chip {
  @apply flex items-center gap-2 px-3 py-2 rounded-lg cursor-pointer transition-all duration-200;
  background: rgba(255, 255, 255, 0.4);
  border: 2px solid transparent;
}

.lang-chip:hover {
  background: rgba(255, 255, 255, 0.6);
}

.lang-chip.active {
  background: rgba(139, 92, 246, 0.1);
  border-color: rgb(139, 92, 246);
}

.lang-icon {
  @apply w-7 h-7 rounded flex items-center justify-center text-white text-xs font-bold;
}

.chat-message {
  @apply p-4 rounded-xl;
}

.chat-message.user {
  @apply bg-blue-500/10 ml-8;
}

.chat-message.assistant {
  @apply bg-white/50 mr-8;
}

.message-header {
  @apply flex items-center justify-between mb-2;
}

.message-role {
  @apply text-xs font-medium text-gray-500;
}

.message-time {
  @apply text-xs text-gray-400;
}

.message-content {
  @apply text-sm text-gray-700 leading-relaxed;
}

.tool-call-card {
  @apply border;
}

.dark-scroll::-webkit-scrollbar {
  width: 6px;
}

.dark-scroll::-webkit-scrollbar-track {
  background: transparent;
}

.dark-scroll::-webkit-scrollbar-thumb {
  background: rgba(0, 0, 0, 0.2);
  border-radius: 3px;
}

.dark-scroll::-webkit-scrollbar-thumb:hover {
  background: rgba(0, 0, 0, 0.3);
}

.spinner {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* 过渡动画 */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
