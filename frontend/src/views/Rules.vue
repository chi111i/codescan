<template>
  <div class="space-y-6 animate-fade-in">
    <!-- 页面标题 -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-3xl font-bold text-white">安全规则</h1>
        <p class="text-white/60 mt-1">查看和管理安全检测规则</p>
      </div>
      <div class="flex items-center gap-2">
        <button
          @click="activeTab = 'builtin'"
          class="px-4 py-2 rounded-lg font-medium transition-all"
          :class="activeTab === 'builtin' ? 'bg-blue-500 text-white' : 'glass-subtle text-gray-600 hover:bg-white/50'"
        >
          内置规则
        </button>
        <button
          @click="activeTab = 'generated'"
          class="px-4 py-2 rounded-lg font-medium transition-all"
          :class="activeTab === 'generated' ? 'bg-blue-500 text-white' : 'glass-subtle text-gray-600 hover:bg-white/50'"
        >
          自动生成
          <span v-if="generatedRules.length > 0" class="ml-1 px-1.5 py-0.5 text-xs rounded-full bg-green-500 text-white">
            {{ generatedRules.length }}
          </span>
        </button>
      </div>
    </div>

    <!-- 内置规则标签页 -->
    <template v-if="activeTab === 'builtin'">
      <!-- 过滤器 -->
      <div class="glass-card rounded-xl p-4 flex flex-wrap gap-4">
        <select v-model="filter.language" class="input-glass w-40">
          <option value="">全部语言</option>
          <option value="python">Python</option>
          <option value="javascript">JavaScript</option>
          <option value="php">PHP</option>
        </select>
        <select v-model="filter.category" class="input-glass w-40">
          <option value="">全部类别</option>
          <option value="injection">注入</option>
          <option value="auth">认证</option>
          <option value="access-control">访问控制</option>
          <option value="file">文件操作</option>
          <option value="crypto">加密</option>
        </select>
        <input
          v-model="filter.search"
          type="text"
          class="input-glass flex-1 min-w-[200px]"
          placeholder="搜索规则..."
        />
      </div>

    <!-- 规则统计 -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
      <div class="glass-card rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-gray-800">{{ rules.length }}</div>
        <div class="text-sm text-gray-500">总规则数</div>
      </div>
      <div class="glass-card rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-red-600">{{ ruleStats.critical }}</div>
        <div class="text-sm text-gray-500">严重</div>
      </div>
      <div class="glass-card rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-orange-600">{{ ruleStats.high }}</div>
        <div class="text-sm text-gray-500">高危</div>
      </div>
      <div class="glass-card rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-yellow-600">{{ ruleStats.medium }}</div>
        <div class="text-sm text-gray-500">中危</div>
      </div>
    </div>

    <!-- 规则列表 -->
    <div class="glass-card rounded-2xl p-6">
      <div class="space-y-3">
        <div
          v-for="rule in filteredRules"
          :key="rule.id"
          class="p-4 rounded-xl bg-white/30 hover:bg-white/50 transition cursor-pointer"
          @click="showRuleDetail(rule)"
        >
          <div class="flex items-start justify-between">
            <div class="flex-1">
              <div class="flex items-center gap-3 mb-2">
                <span
                  class="px-2 py-1 rounded text-xs font-medium"
                  :class="getRiskClass(rule.risk_level)"
                >
                  {{ getRiskText(rule.risk_level) }}
                </span>
                <span class="text-xs text-gray-500">{{ rule.id }}</span>
              </div>
              <h3 class="font-medium text-gray-800">{{ rule.name }}</h3>
              <p class="text-sm text-gray-500 mt-1">{{ rule.description }}</p>
            </div>
            <div class="flex flex-wrap gap-1 ml-4">
              <span
                v-for="lang in rule.languages"
                :key="lang"
                class="px-2 py-0.5 text-xs bg-white/50 rounded capitalize"
              >
                {{ lang }}
              </span>
            </div>
          </div>
        </div>

        <div v-if="filteredRules.length === 0" class="text-center py-12 text-gray-500">
          暂无符合条件的规则
        </div>
      </div>
    </div>
    </template>

    <!-- 自动生成规则标签页 -->
    <template v-if="activeTab === 'generated'">
      <!-- 统计信息 -->
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div class="glass-card rounded-xl p-4 text-center">
          <div class="text-2xl font-bold text-gray-800">{{ generatedRules.length }}</div>
          <div class="text-sm text-gray-500">总规则数</div>
        </div>
        <div class="glass-card rounded-xl p-4 text-center">
          <div class="text-2xl font-bold text-green-600">{{ approvedRulesCount }}</div>
          <div class="text-sm text-gray-500">已批准</div>
        </div>
        <div class="glass-card rounded-xl p-4 text-center">
          <div class="text-2xl font-bold text-yellow-600">{{ pendingRulesCount }}</div>
          <div class="text-sm text-gray-500">待审核</div>
        </div>
        <div class="glass-card rounded-xl p-4 text-center">
          <div class="text-2xl font-bold text-blue-600">{{ generatedRulesStats.total_patterns || 0 }}</div>
          <div class="text-sm text-gray-500">关联模式</div>
        </div>
      </div>

      <!-- 自动生成规则列表 -->
      <div class="glass-card rounded-2xl p-6">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-lg font-semibold text-gray-800">自动生成的规则</h2>
          <button @click="loadGeneratedRules" class="btn-secondary text-sm">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
            刷新
          </button>
        </div>

        <div class="space-y-4">
          <div
            v-for="rule in generatedRules"
            :key="rule.id"
            class="p-4 rounded-xl bg-white/30 hover:bg-white/50 transition"
          >
            <div class="flex items-start justify-between mb-3">
              <div class="flex-1">
                <div class="flex items-center gap-3 mb-2">
                  <span
                    class="px-2 py-1 rounded text-xs font-medium"
                    :class="rule.approved ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'"
                  >
                    {{ rule.approved ? '已批准' : '待审核' }}
                  </span>
                  <span class="text-xs px-2 py-0.5 rounded-full bg-purple-100 text-purple-700">
                    {{ rule.rule_type }}
                  </span>
                  <span class="text-xs text-gray-500">{{ rule.id }}</span>
                </div>
                <h3 class="font-medium text-gray-800">{{ rule.name }}</h3>
                <p class="text-sm text-gray-500 mt-1">{{ rule.description || rule.detection_logic }}</p>
              </div>
              <div class="flex items-center gap-2">
                <button
                  v-if="!rule.approved"
                  @click="approveGeneratedRule(rule.id)"
                  class="p-2 rounded-lg hover:bg-green-100 text-green-600"
                  title="批准规则"
                >
                  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                  </svg>
                </button>
                <button
                  @click="showGeneratedRuleDetail(rule)"
                  class="p-2 rounded-lg hover:bg-blue-100 text-blue-600"
                  title="查看详情"
                >
                  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                  </svg>
                </button>
                <button
                  @click="deleteGeneratedRule(rule.id)"
                  class="p-2 rounded-lg hover:bg-red-100 text-red-600"
                  title="删除规则"
                >
                  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                  </svg>
                </button>
              </div>
            </div>

            <!-- 规则内容预览 -->
            <div class="flex flex-wrap gap-2 mb-3">
              <span
                v-for="lang in rule.languages || []"
                :key="lang"
                class="px-2 py-0.5 text-xs bg-blue-100 text-blue-700 rounded"
              >
                {{ lang }}
              </span>
              <span
                v-for="fw in rule.frameworks || []"
                :key="fw"
                class="px-2 py-0.5 text-xs bg-purple-100 text-purple-700 rounded"
              >
                {{ fw }}
              </span>
            </div>

            <!-- 匹配模式预览 -->
            <div v-if="rule.rule_content?.patterns" class="bg-gray-100 rounded-lg p-3">
              <div class="text-xs text-gray-500 mb-1">匹配模式:</div>
              <code class="text-xs font-mono text-gray-700">
                {{ (rule.rule_content.patterns || []).slice(0, 2).join(' | ') }}
                <span v-if="(rule.rule_content.patterns || []).length > 2" class="text-gray-400">
                  +{{ rule.rule_content.patterns.length - 2 }} more
                </span>
              </code>
            </div>
          </div>

          <div v-if="generatedRules.length === 0" class="text-center py-12">
            <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
            </svg>
            <p class="text-gray-500 mb-2">暂无自动生成的规则</p>
            <p class="text-sm text-gray-400">在变体分析页面确认漏洞后可自动生成规则</p>
          </div>
        </div>
      </div>
    </template>

    <!-- 规则详情弹窗 -->
    <div
      v-if="selectedRule"
      class="fixed inset-0 z-50 flex items-center justify-center p-6"
      @click.self="selectedRule = null"
    >
      <div class="absolute inset-0 bg-black/30 backdrop-blur-sm"></div>
      <div class="relative glass-card rounded-2xl p-6 max-w-2xl w-full max-h-[80vh] overflow-y-auto animate-slide-up">
        <button
          @click="selectedRule = null"
          class="absolute top-4 right-4 p-2 rounded-lg hover:bg-white/30"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </button>

        <div class="space-y-6">
          <div>
            <span
              class="px-3 py-1 rounded-full text-sm font-medium"
              :class="getRiskClass(selectedRule.risk_level)"
            >
              {{ getRiskText(selectedRule.risk_level) }}
            </span>
            <h2 class="text-xl font-bold text-gray-800 mt-3">{{ selectedRule.name }}</h2>
            <p class="text-sm text-gray-500 mt-1">{{ selectedRule.id }}</p>
          </div>

          <div class="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span class="text-gray-500">类型</span>
              <p class="font-medium text-gray-800">{{ selectedRule.rule_type }}</p>
            </div>
            <div>
              <span class="text-gray-500">类别</span>
              <p class="font-medium text-gray-800">{{ selectedRule.category }}</p>
            </div>
          </div>

          <div>
            <span class="text-sm text-gray-500">支持语言</span>
            <div class="flex flex-wrap gap-2 mt-2">
              <span
                v-for="lang in selectedRule.languages"
                :key="lang"
                class="px-3 py-1 bg-blue-100 text-blue-700 rounded-lg text-sm capitalize"
              >
                {{ lang }}
              </span>
            </div>
          </div>

          <div>
            <span class="text-sm text-gray-500">描述</span>
            <p class="text-gray-700 mt-1">{{ selectedRule.description }}</p>
          </div>

          <div v-if="selectedRule.patterns?.length > 0">
            <span class="text-sm text-gray-500">匹配模式</span>
            <div class="mt-2 space-y-2">
              <code
                v-for="(pattern, idx) in selectedRule.patterns"
                :key="idx"
                class="block px-3 py-2 bg-gray-100 rounded-lg text-sm font-mono"
              >
                {{ pattern }}
              </code>
            </div>
          </div>

          <div>
            <span class="text-sm text-gray-500">修复建议</span>
            <p class="text-gray-700 mt-1">{{ selectedRule.fix_suggestion }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useAppStore } from '../stores/app'

const API_BASE = 'http://localhost:8000/api'

const appStore = useAppStore()

const activeTab = ref('builtin')
const selectedRule = ref(null)
const selectedGeneratedRule = ref(null)
const generatedRules = ref([])
const generatedRulesStats = ref({})

const filter = reactive({
  language: '',
  category: '',
  search: '',
})

const rules = computed(() => appStore.rules)

const filteredRules = computed(() => {
  return rules.value.filter(r => {
    if (filter.language && !r.languages.includes(filter.language)) return false
    if (filter.category && r.category !== filter.category) return false
    if (filter.search) {
      const search = filter.search.toLowerCase()
      if (!r.name.toLowerCase().includes(search) &&
          !r.description.toLowerCase().includes(search) &&
          !r.id.toLowerCase().includes(search)) {
        return false
      }
    }
    return true
  })
})

const ruleStats = computed(() => {
  const stats = { critical: 0, high: 0, medium: 0, low: 0 }
  rules.value.forEach(r => {
    if (r.risk_level in stats) stats[r.risk_level]++
  })
  return stats
})

const approvedRulesCount = computed(() => {
  return generatedRules.value.filter(r => r.approved).length
})

const pendingRulesCount = computed(() => {
  return generatedRules.value.filter(r => !r.approved).length
})

const getRiskClass = (risk) => {
  const classes = {
    critical: 'bg-red-100 text-red-700',
    high: 'bg-orange-100 text-orange-700',
    medium: 'bg-yellow-100 text-yellow-700',
    low: 'bg-blue-100 text-blue-700',
  }
  return classes[risk] || 'bg-gray-100 text-gray-700'
}

const getRiskText = (risk) => {
  const texts = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
  }
  return texts[risk] || risk
}

const showRuleDetail = (rule) => {
  selectedRule.value = rule
}

const showGeneratedRuleDetail = (rule) => {
  selectedRule.value = {
    ...rule,
    patterns: rule.rule_content?.patterns || [],
    fix_suggestion: rule.rule_content?.fix_suggestion || '',
    risk_level: rule.rule_content?.severity || 'medium',
  }
}

const loadGeneratedRules = async () => {
  try {
    const [rulesRes, statsRes] = await Promise.all([
      fetch(`${API_BASE}/variant/rules`),
      fetch(`${API_BASE}/variant/stats`),
    ])

    const rulesData = await rulesRes.json()
    const statsData = await statsRes.json()

    if (rulesData.success) {
      generatedRules.value = rulesData.rules
    }
    if (statsData.success) {
      generatedRulesStats.value = statsData.stats
    }
  } catch (e) {
    console.error('Failed to load generated rules:', e)
  }
}

const approveGeneratedRule = async (ruleId) => {
  try {
    const res = await fetch(`${API_BASE}/variant/rules/${ruleId}/approve`, {
      method: 'POST',
    })
    const data = await res.json()
    if (data.success) {
      const rule = generatedRules.value.find(r => r.id === ruleId)
      if (rule) rule.approved = true
    }
  } catch (e) {
    console.error('Failed to approve rule:', e)
  }
}

const deleteGeneratedRule = async (ruleId) => {
  if (!confirm('确定要删除这条规则吗？')) return

  try {
    const res = await fetch(`${API_BASE}/variant/rules/${ruleId}`, {
      method: 'DELETE',
    })
    const data = await res.json()
    if (data.success) {
      generatedRules.value = generatedRules.value.filter(r => r.id !== ruleId)
    }
  } catch (e) {
    console.error('Failed to delete rule:', e)
  }
}

onMounted(() => {
  appStore.fetchRules()
  loadGeneratedRules()
})
</script>
