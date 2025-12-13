<template>
  <div class="space-y-6">
    <!-- 页面标题 -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-3xl font-bold text-white mb-2">变体分析</h1>
        <p class="text-white/60">发现一个漏洞，挖出一串兄弟漏洞</p>
      </div>
      <div class="flex items-center gap-4">
        <div class="glass-subtle px-4 py-2 rounded-lg">
          <span class="text-sm text-gray-400">已确认模式:</span>
          <span class="text-lg font-bold text-white ml-2">{{ stats.total_patterns }}</span>
        </div>
        <div class="glass-subtle px-4 py-2 rounded-lg">
          <span class="text-sm text-gray-400">发现变体:</span>
          <span class="text-lg font-bold text-green-400 ml-2">{{ stats.total_variants_found }}</span>
        </div>
      </div>
    </div>

    <!-- 主要内容区 -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- 左侧：确认漏洞 -->
      <div class="lg:col-span-1 space-y-6">
        <!-- 确认漏洞表单 -->
        <div class="glass-card p-6">
          <h2 class="text-xl font-semibold text-gray-800 mb-4 flex items-center gap-2">
            <div class="w-8 h-8 rounded-lg bg-red-100 flex items-center justify-center">
              <svg class="w-4 h-4 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
              </svg>
            </div>
            确认漏洞
          </h2>

          <div class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">漏洞类型</label>
              <select v-model="newFinding.issue_type" class="select-glass">
                <option value="rce">远程代码执行 (RCE)</option>
                <option value="sqli">SQL 注入</option>
                <option value="xss">跨站脚本 (XSS)</option>
                <option value="idor">越权访问 (IDOR)</option>
                <option value="auth_bypass">认证绕过</option>
                <option value="ssrf">服务端请求伪造 (SSRF)</option>
                <option value="file_upload">任意文件上传</option>
                <option value="path_traversal">路径穿越</option>
                <option value="deserialization">不安全反序列化</option>
                <option value="business_logic">业务逻辑漏洞</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">严重程度</label>
              <div class="flex gap-2">
                <button
                  v-for="sev in severities"
                  :key="sev.value"
                  @click="newFinding.severity = sev.value"
                  class="flex-1 py-2 px-3 rounded-lg text-sm font-medium transition-all"
                  :class="newFinding.severity === sev.value ? sev.activeClass : 'glass-subtle text-gray-600 hover:bg-gray-100'"
                >
                  {{ sev.label }}
                </button>
              </div>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">漏洞描述</label>
              <textarea
                v-model="newFinding.summary"
                rows="3"
                class="input-glass"
                placeholder="简要描述漏洞..."
              ></textarea>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">相关代码</label>
              <textarea
                v-model="codeContext"
                rows="8"
                class="input-glass font-mono text-sm"
                placeholder="粘贴相关代码片段..."
              ></textarea>
            </div>

            <button
              @click="confirmVulnerability"
              :disabled="confirming || !codeContext"
              class="btn-primary w-full"
            >
              <svg v-if="confirming" class="w-5 h-5 spinner mr-2" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              {{ confirming ? '确认中...' : '确认并创建模式' }}
            </button>
          </div>
        </div>

        <!-- 已确认的模式列表 -->
        <div class="glass-card p-6">
          <h2 class="text-xl font-semibold text-gray-800 mb-4">已确认模式</h2>
          <div class="space-y-3 max-h-96 overflow-y-auto">
            <div
              v-for="pattern in patterns"
              :key="pattern.id"
              @click="selectPattern(pattern)"
              class="p-3 glass-subtle rounded-lg cursor-pointer hover:bg-blue-50 transition-colors"
              :class="{ 'ring-2 ring-blue-500': selectedPattern?.id === pattern.id }"
            >
              <div class="flex items-center justify-between mb-1">
                <span class="font-medium text-gray-800">{{ pattern.name }}</span>
                <span
                  class="text-xs px-2 py-0.5 rounded-full"
                  :class="getSeverityClass(pattern.severity)"
                >
                  {{ pattern.severity }}
                </span>
              </div>
              <div class="text-xs text-gray-500">
                {{ pattern.id }} | 发现 {{ pattern.variants_found }} 个变体
              </div>
            </div>
            <div v-if="patterns.length === 0" class="text-center py-8 text-gray-400">
              暂无已确认的漏洞模式
            </div>
          </div>
        </div>
      </div>

      <!-- 中间：变体搜索结果 -->
      <div class="lg:col-span-2 space-y-6">
        <!-- 搜索控制 -->
        <div class="glass-card p-6" v-if="selectedPattern">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h2 class="text-xl font-semibold text-gray-800">搜索变体</h2>
              <p class="text-sm text-gray-500">基于模式 {{ selectedPattern.id }} 搜索相似漏洞</p>
            </div>
            <div class="flex items-center gap-4">
              <div class="flex items-center gap-2">
                <label class="text-sm text-gray-600">相似度阈值:</label>
                <input
                  v-model.number="searchConfig.similarity_threshold"
                  type="range"
                  min="0.5"
                  max="0.95"
                  step="0.05"
                  class="w-24"
                />
                <span class="text-sm text-gray-700 w-12">{{ searchConfig.similarity_threshold }}</span>
              </div>
              <label class="flex items-center gap-2 text-sm text-gray-600">
                <input type="checkbox" v-model="searchConfig.use_llm_verification" class="rounded" />
                LLM 验证
              </label>
              <button
                @click="searchVariants"
                :disabled="searching"
                class="btn-primary"
              >
                <svg v-if="searching" class="w-5 h-5 spinner mr-2" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                {{ searching ? '搜索中...' : '搜索变体' }}
              </button>
            </div>
          </div>

          <!-- 搜索结果 -->
          <div class="space-y-4">
            <div v-if="variants.length > 0" class="text-sm text-gray-600 mb-2">
              找到 {{ variants.length }} 个潜在变体
            </div>

            <div
              v-for="variant in variants"
              :key="variant.id"
              class="glass-subtle rounded-lg p-4 hover:bg-gray-50 transition-colors"
            >
              <div class="flex items-start justify-between mb-3">
                <div>
                  <div class="flex items-center gap-2 mb-1">
                    <span class="font-medium text-gray-800">{{ variant.function_name }}</span>
                    <span class="text-xs px-2 py-0.5 rounded-full bg-blue-100 text-blue-700">
                      {{ (variant.similarity_score * 100).toFixed(0) }}% 相似
                    </span>
                    <span
                      v-if="variant.llm_verified"
                      class="text-xs px-2 py-0.5 rounded-full"
                      :class="variant.llm_confidence > 0.7 ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'"
                    >
                      LLM: {{ (variant.llm_confidence * 100).toFixed(0) }}%
                    </span>
                  </div>
                  <div class="text-sm text-gray-500">
                    {{ variant.file_path }}:{{ variant.line_start }}-{{ variant.line_end }}
                  </div>
                </div>
                <div class="flex items-center gap-2">
                  <button
                    @click="confirmVariant(variant, true)"
                    class="p-2 rounded-lg hover:bg-green-100 text-green-600"
                    title="确认为漏洞"
                  >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                    </svg>
                  </button>
                  <button
                    @click="confirmVariant(variant, false)"
                    class="p-2 rounded-lg hover:bg-red-100 text-red-600"
                    title="标记为误报"
                  >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                  </button>
                </div>
              </div>

              <!-- 代码片段 -->
              <div class="bg-gray-900 rounded-lg p-3 overflow-x-auto">
                <pre class="text-sm text-gray-100 font-mono">{{ variant.code_snippet }}</pre>
              </div>

              <!-- LLM 解释 -->
              <div v-if="variant.llm_explanation" class="mt-3 p-3 glass-blue rounded-lg">
                <div class="flex items-start gap-2">
                  <svg class="w-5 h-5 text-blue-600 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
                  </svg>
                  <p class="text-sm text-gray-700">{{ variant.llm_explanation }}</p>
                </div>
              </div>
            </div>

            <div v-if="variants.length === 0 && !searching" class="text-center py-12 text-gray-400">
              <svg class="w-12 h-12 mx-auto mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
              </svg>
              <p>点击"搜索变体"开始搜索相似漏洞</p>
            </div>
          </div>
        </div>

        <!-- 规则生成 -->
        <div class="glass-card p-6" v-if="selectedPattern">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h2 class="text-xl font-semibold text-gray-800">自动生成规则</h2>
              <p class="text-sm text-gray-500">将漏洞模式转化为可复用的检测规则</p>
            </div>
            <div class="flex items-center gap-4">
              <select v-model="ruleType" class="select-glass w-40">
                <option value="semantic">语义规则</option>
                <option value="regex">正则规则</option>
                <option value="ast">AST 规则</option>
              </select>
              <button
                @click="generateRule"
                :disabled="generatingRule"
                class="btn-secondary"
              >
                <svg v-if="generatingRule" class="w-5 h-5 spinner mr-2" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                {{ generatingRule ? '生成中...' : '生成规则' }}
              </button>
            </div>
          </div>

          <!-- 生成的规则预览 -->
          <div v-if="generatedRule" class="glass-subtle rounded-lg p-4">
            <div class="flex items-center justify-between mb-3">
              <div>
                <span class="font-medium text-gray-800">{{ generatedRule.name }}</span>
                <span
                  class="ml-2 text-xs px-2 py-0.5 rounded-full"
                  :class="generatedRule.approved ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'"
                >
                  {{ generatedRule.approved ? '已批准' : '待审核' }}
                </span>
              </div>
              <div class="flex items-center gap-2">
                <button
                  v-if="!generatedRule.approved"
                  @click="approveRule(generatedRule.id)"
                  class="btn-primary text-sm py-1 px-3"
                >
                  批准规则
                </button>
                <button
                  @click="deleteRule(generatedRule.id)"
                  class="btn-secondary text-sm py-1 px-3 text-red-600"
                >
                  删除
                </button>
              </div>
            </div>

            <div class="text-sm text-gray-600 mb-3">
              {{ generatedRule.detection_logic }}
            </div>

            <div class="bg-gray-900 rounded-lg p-3 overflow-x-auto">
              <pre class="text-sm text-gray-100 font-mono">{{ JSON.stringify(generatedRule.rule_content, null, 2) }}</pre>
            </div>

            <div class="flex flex-wrap gap-2 mt-3">
              <span
                v-for="lang in generatedRule.languages"
                :key="lang"
                class="text-xs px-2 py-1 rounded-full bg-blue-100 text-blue-700"
              >
                {{ lang }}
              </span>
              <span
                v-for="fw in generatedRule.frameworks"
                :key="fw"
                class="text-xs px-2 py-1 rounded-full bg-purple-100 text-purple-700"
              >
                {{ fw }}
              </span>
            </div>
          </div>
        </div>

        <!-- 未选择模式时的提示 -->
        <div v-if="!selectedPattern" class="glass-card p-12 text-center">
          <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
          </svg>
          <h3 class="text-xl font-semibold text-gray-700 mb-2">选择或创建漏洞模式</h3>
          <p class="text-gray-500">从左侧确认一个新漏洞，或选择已有模式开始变体分析</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed } from 'vue'

// API 基础URL
const API_BASE = 'http://localhost:8000/api'

// 状态
const patterns = ref([])
const variants = ref([])
const selectedPattern = ref(null)
const generatedRule = ref(null)
const stats = ref({
  total_patterns: 0,
  total_variants_found: 0,
})

// 加载状态
const confirming = ref(false)
const searching = ref(false)
const generatingRule = ref(false)

// 表单数据
const newFinding = reactive({
  issue_type: 'rce',
  severity: 'high',
  summary: '',
})
const codeContext = ref('')
const ruleType = ref('semantic')

const searchConfig = reactive({
  top_k: 20,
  similarity_threshold: 0.75,
  use_llm_verification: true,
})

const severities = [
  { value: 'critical', label: '严重', activeClass: 'bg-red-500 text-white' },
  { value: 'high', label: '高危', activeClass: 'bg-orange-500 text-white' },
  { value: 'medium', label: '中危', activeClass: 'bg-yellow-500 text-white' },
  { value: 'low', label: '低危', activeClass: 'bg-blue-500 text-white' },
]

// 方法
const loadPatterns = async () => {
  try {
    const res = await fetch(`${API_BASE}/variant/patterns`)
    const data = await res.json()
    if (data.success) {
      patterns.value = data.patterns
    }
  } catch (e) {
    console.error('Failed to load patterns:', e)
  }
}

const loadStats = async () => {
  try {
    const res = await fetch(`${API_BASE}/variant/stats`)
    const data = await res.json()
    if (data.success) {
      stats.value = data.stats
    }
  } catch (e) {
    console.error('Failed to load stats:', e)
  }
}

const confirmVulnerability = async () => {
  if (!codeContext.value) return

  confirming.value = true
  try {
    const res = await fetch(`${API_BASE}/variant/confirm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        finding_id: `F-${Date.now()}`,
        finding: newFinding,
        code_context: codeContext.value,
      }),
    })
    const data = await res.json()
    if (data.success) {
      await loadPatterns()
      await loadStats()
      selectPattern(data.pattern)
      // 清空表单
      codeContext.value = ''
      newFinding.summary = ''
    }
  } catch (e) {
    console.error('Failed to confirm vulnerability:', e)
  } finally {
    confirming.value = false
  }
}

const selectPattern = (pattern) => {
  selectedPattern.value = pattern
  variants.value = []
  generatedRule.value = null
}

const searchVariants = async () => {
  if (!selectedPattern.value) return

  searching.value = true
  try {
    const res = await fetch(`${API_BASE}/variant/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pattern_id: selectedPattern.value.id,
        ...searchConfig,
      }),
    })
    const data = await res.json()
    if (data.success) {
      variants.value = data.variants
    }
  } catch (e) {
    console.error('Failed to search variants:', e)
  } finally {
    searching.value = false
  }
}

const confirmVariant = async (variant, isTruePositive) => {
  try {
    const res = await fetch(`${API_BASE}/variant/confirm-variant`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        variant_id: variant.id,
        is_true_positive: isTruePositive,
        confirmed_by: 'user',
      }),
    })
    const data = await res.json()
    if (data.success) {
      variant.status = isTruePositive ? 'confirmed' : 'false_positive'
      // 刷新统计
      await loadStats()
    }
  } catch (e) {
    console.error('Failed to confirm variant:', e)
  }
}

const generateRule = async () => {
  if (!selectedPattern.value) return

  generatingRule.value = true
  try {
    const res = await fetch(`${API_BASE}/variant/generate-rule`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pattern_id: selectedPattern.value.id,
        rule_type: ruleType.value,
      }),
    })
    const data = await res.json()
    if (data.success) {
      generatedRule.value = data.rule
    }
  } catch (e) {
    console.error('Failed to generate rule:', e)
  } finally {
    generatingRule.value = false
  }
}

const approveRule = async (ruleId) => {
  try {
    const res = await fetch(`${API_BASE}/variant/rules/${ruleId}/approve`, {
      method: 'POST',
    })
    const data = await res.json()
    if (data.success && generatedRule.value) {
      generatedRule.value.approved = true
    }
  } catch (e) {
    console.error('Failed to approve rule:', e)
  }
}

const deleteRule = async (ruleId) => {
  if (!confirm('确定要删除这条规则吗？')) return

  try {
    const res = await fetch(`${API_BASE}/variant/rules/${ruleId}`, {
      method: 'DELETE',
    })
    const data = await res.json()
    if (data.success) {
      generatedRule.value = null
    }
  } catch (e) {
    console.error('Failed to delete rule:', e)
  }
}

const getSeverityClass = (severity) => {
  const classes = {
    critical: 'bg-red-100 text-red-700',
    high: 'bg-orange-100 text-orange-700',
    medium: 'bg-yellow-100 text-yellow-700',
    low: 'bg-blue-100 text-blue-700',
  }
  return classes[severity] || 'bg-gray-100 text-gray-700'
}

onMounted(() => {
  loadPatterns()
  loadStats()
})
</script>
