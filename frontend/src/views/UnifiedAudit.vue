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
    <div v-if="!currentSession" class="flex-1 flex items-center justify-center">
      <!-- 快速扫描模式 -->
      <div v-if="auditMode === 'quick-scan'" class="glass-card rounded-2xl p-8 max-w-2xl w-full">
        <div class="text-center mb-6">
          <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-blue-500 to-cyan-600 flex items-center justify-center shadow-lg shadow-blue-500/30">
            <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
            </svg>
          </div>
          <h2 class="text-2xl font-bold text-gray-800 mb-2">快速安全扫描</h2>
          <p class="text-gray-500">配置扫描参数，批量检测安全漏洞</p>
        </div>

        <!-- 快速扫描配置面板 -->
        <ScanConfigPanel
          :is-scanning="isQuickScanning"
          @start-scan="handleQuickScan"
        />

        <!-- 扫描进度显示 -->
        <div v-if="quickScanProgress" class="mt-6 p-4 rounded-xl bg-blue-50 border border-blue-100">
          <div class="flex items-center justify-between mb-2">
            <span class="text-sm font-medium text-blue-700">{{ quickScanProgress.current_step || '扫描中...' }}</span>
            <span class="text-sm text-blue-600">{{ Math.round((quickScanProgress.progress || 0) * 100) }}%</span>
          </div>
          <div class="w-full h-2 bg-blue-100 rounded-full overflow-hidden">
            <div
              class="h-full bg-gradient-to-r from-blue-500 to-cyan-500 transition-all duration-300"
              :style="{ width: `${(quickScanProgress.progress || 0) * 100}%` }"
            ></div>
          </div>
          <p v-if="quickScanProgress.details" class="mt-2 text-xs text-blue-600">{{ quickScanProgress.details }}</p>
        </div>

        <!-- 扫描完成后显示结果链接 -->
        <div v-if="quickScanResult" class="mt-6 p-4 rounded-xl bg-green-50 border border-green-100">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 rounded-full bg-green-500 flex items-center justify-center">
                <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                </svg>
              </div>
              <div>
                <div class="font-medium text-green-800">扫描完成</div>
                <div class="text-sm text-green-600">
                  发现 {{ quickScanResult.findings_count || 0 }} 个问题
                </div>
              </div>
            </div>
            <div class="flex gap-2">
              <router-link
                :to="`/results/${quickScanResult.scan_id}`"
                class="btn-primary text-sm"
              >
                查看结果
              </router-link>
              <button
                @click="continueInConversation"
                class="btn-secondary text-sm"
              >
                对话深入分析
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- 对话审计模式（原有界面） -->
      <div v-else class="glass-card rounded-2xl p-8 max-w-xl w-full">
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
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { useRoute, useRouter, onBeforeRouteLeave } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useAuditStore } from '../stores/auditStore'
import ScanConfigPanel from '../components/ScanConfigPanel.vue'
import LLMCallCard from '../components/LLMCallCard.vue'
import FindingCard from '../components/FindingCard.vue'
import AnalysisProgressBar from '../components/AnalysisProgressBar.vue'

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
</style>
