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
      <div class="col-span-9 glass-card rounded-2xl p-4 flex flex-col min-h-0 overflow-hidden">
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
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import * as api from '../api'
import ScanConfigPanel from '../components/ScanConfigPanel.vue'

// ============ 状态 ============

// 审计模式
const auditMode = ref('conversation') // 'conversation' | 'quick-scan'

// 会话管理
const currentSession = ref(null)
const existingSessions = ref([])
const isCreatingSession = ref(false)
const newSessionConfig = reactive({
  targetPath: '',
  languages: [],
  enableCallChain: true,
  enableVariantAnalysis: true,
})

// 快速扫描状态
const isQuickScanning = ref(false)
const quickScanProgress = ref(null)
const quickScanResult = ref(null)
let quickScanWs = null

// 工具
const availableTools = ref([])
const toolCallHistory = ref([])

// 对话
const chatMessages = ref([])
const chatInput = ref('')
const isProcessing = ref(false)
const currentProcessingStep = ref('')
const chatContainer = ref(null)

// 统计
const sessionStats = ref({})

// WebSocket
let ws = null

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

// ============ 方法 ============

// 会话管理
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

const createSession = async () => {
  if (!newSessionConfig.targetPath) return

  isCreatingSession.value = true
  try {
    const result = await api.createUnifiedSession({
      target_path: newSessionConfig.targetPath,
      languages: newSessionConfig.languages.length > 0 ? newSessionConfig.languages : null,
      enable_call_chain: newSessionConfig.enableCallChain,
      enable_variant_analysis: newSessionConfig.enableVariantAnalysis,
    })

    if (result.success) {
      currentSession.value = result.data
      await loadSessionData(result.data.session_id)
      connectWebSocket(result.data.session_id)
    }
  } catch (error) {
    console.error('创建会话失败:', error)
    alert('创建会话失败: ' + (error.response?.data?.detail || error.message))
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
    }
  } catch (error) {
    console.error('加载会话失败:', error)
    alert('加载会话失败')
  }
}

const loadSessionData = async (sessionId) => {
  try {
    // 并行加载数据
    const [toolsResult, messagesResult, toolCallsResult, statsResult] = await Promise.all([
      api.getAgentTools(sessionId),
      api.getAgentMessages(sessionId),
      api.getAgentToolCalls(sessionId),
      api.getAgentStats(sessionId),
    ])

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
  if (!confirm('确定要删除该会话吗？')) return

  try {
    await api.deleteUnifiedSession(sessionId)
    existingSessions.value = existingSessions.value.filter(s => s.session_id !== sessionId)
    if (currentSession.value?.session_id === sessionId) {
      currentSession.value = null
      disconnectWebSocket()
    }
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
    await api.clearAgentHistory(currentSession.value.session_id)
    chatMessages.value = []
    toolCallHistory.value = []
  } catch (error) {
    console.error('清空历史失败:', error)
  }
}

// ============ 快速扫描功能 ============

const handleQuickScan = async (config) => {
  if (isQuickScanning.value) return

  isQuickScanning.value = true
  quickScanProgress.value = { progress: 0, current_step: '正在初始化...' }
  quickScanResult.value = null

  try {
    // 发起扫描请求
    const result = await api.startScan(config)

    if (result.success && result.data.scan_id) {
      const scanId = result.data.scan_id
      // 连接 WebSocket 监听进度
      connectQuickScanWebSocket(scanId)
    } else {
      throw new Error(result.error || '启动扫描失败')
    }
  } catch (error) {
    console.error('快速扫描失败:', error)
    alert('启动扫描失败: ' + (error.response?.data?.detail || error.message))
    isQuickScanning.value = false
    quickScanProgress.value = null
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
      quickScanProgress.value = {
        progress: data.progress || 0,
        current_step: data.current_step || '扫描中...',
        details: data.details || '',
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
      alert('扫描出错: ' + data.error)
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

const continueInConversation = async () => {
  if (!quickScanResult.value) return

  // 切换到对话模式
  auditMode.value = 'conversation'

  // 预填充目标路径
  newSessionConfig.targetPath = quickScanResult.value.target_path || ''

  // 清空快速扫描结果
  quickScanResult.value = null
}

// 对话交互
const sendMessage = async () => {
  if (!chatInput.value.trim() || !currentSession.value || isProcessing.value) return

  const message = chatInput.value.trim()
  chatInput.value = ''

  // 添加用户消息
  chatMessages.value.push({
    role: 'user',
    content: message,
    timestamp: new Date(),
  })

  isProcessing.value = true
  currentProcessingStep.value = '正在分析...'

  try {
    const result = await api.chatWithAgent(currentSession.value.session_id, message)

    if (result.success && result.data.message) {
      const msg = result.data.message
      chatMessages.value.push({
        role: 'assistant',
        content: msg.content,
        tool_calls: msg.tool_calls || [],
        timestamp: new Date(msg.timestamp || Date.now()),
      })

      // 更新工具调用历史
      if (msg.tool_calls && msg.tool_calls.length > 0) {
        toolCallHistory.value.push(...msg.tool_calls)
      }

      // 更新统计
      sessionStats.value.total_llm_calls = (sessionStats.value.total_llm_calls || 0) + 1

      scrollToBottom()
    }
  } catch (error) {
    console.error('对话失败:', error)
    chatMessages.value.push({
      role: 'assistant',
      content: '处理失败: ' + (error.response?.data?.detail || error.message),
      timestamp: new Date(),
    })
  } finally {
    isProcessing.value = false
    currentProcessingStep.value = ''
  }
}

const sendQuickMessage = (message) => {
  chatInput.value = message
  sendMessage()
}

// 工具相关
const showToolDetail = (tool) => {
  // 可以显示工具详情弹窗
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

// WebSocket
let wsReconnectTimer = null
let wsReconnectAttempts = 0
const WS_MAX_RECONNECT_ATTEMPTS = 5
const WS_RECONNECT_DELAY = 3000

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
      if (currentSession.value && event.code !== 1000 && wsReconnectAttempts < WS_MAX_RECONNECT_ATTEMPTS) {
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

const handleWebSocketMessage = (data) => {
  switch (data.type) {
    case 'connected':
      console.log('WebSocket connected:', data)
      break
    case 'tool_call_start':
      currentProcessingStep.value = `调用工具: ${data.data?.tool_name || ''}`
      break
    case 'tool_call_end':
      if (data.data) {
        toolCallHistory.value.push(data.data)
      }
      break
    case 'message_chunk':
      // 流式响应处理
      break
    case 'message_complete':
      if (data.data) {
        chatMessages.value.push({
          role: 'assistant',
          content: data.data.content,
          tool_calls: data.data.tool_calls || [],
          timestamp: new Date(),
        })
        scrollToBottom()
      }
      isProcessing.value = false
      break
    case 'error':
      console.error('WebSocket error:', data.data?.error)
      isProcessing.value = false
      break
  }
}

// 工具函数
const scrollToBottom = () => {
  nextTick(() => {
    if (chatContainer.value) {
      chatContainer.value.scrollTop = chatContainer.value.scrollHeight
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

const renderMarkdown = (text) => {
  if (!text) return ''
  return text
    .replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre class="bg-gray-900 text-gray-100 p-3 rounded-lg overflow-x-auto text-xs my-2"><code>$2</code></pre>')
    .replace(/`([^`]+)`/g, '<code class="bg-gray-100 px-1 rounded text-sm">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br>')
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

onMounted(() => {
  fetchExistingSessions()
})

onUnmounted(() => {
  disconnectWebSocket()
  disconnectQuickScanWebSocket()
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
