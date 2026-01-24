<template>
  <div class="space-y-6 animate-fade-in">
    <!-- 页面标题 -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold text-gray-900">安全规则</h1>
        <p class="text-gray-500 text-sm mt-1">查看和管理安全检测规则</p>
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
          <option value="typescript">TypeScript</option>
          <option value="php">PHP</option>
          <option value="java">Java</option>
          <option value="go">Go</option>
          <option value="ruby">Ruby</option>
          <option value="csharp">C#</option>
          <option value="dockerfile">Dockerfile</option>
          <option value="yaml">YAML</option>
          <option value="hcl">HCL (Terraform)</option>
        </select>
        <select v-model="filter.category" class="input-glass w-40">
          <option value="">全部类别</option>
          <option value="injection">注入</option>
          <option value="auth">认证</option>
          <option value="access-control">访问控制</option>
          <option value="business-logic">业务逻辑</option>
          <option value="file">文件操作</option>
          <option value="file-upload">文件上传</option>
          <option value="crypto">加密</option>
          <option value="ssrf">SSRF</option>
          <option value="xss">XSS</option>
          <option value="xxe">XXE</option>
          <option value="deserialization">反序列化</option>
          <option value="api-security">API安全</option>
          <option value="cloud-native">云原生</option>
          <option value="supply-chain">供应链</option>
        </select>
        <div class="relative flex-1 min-w-[200px]">
          <input
            v-model="filter.search"
            type="text"
            class="input-glass w-full pr-8"
            placeholder="搜索规则..."
          />
          <!-- 搜索清空按钮 -->
          <button
            v-if="filter.search"
            @click="filter.search = ''"
            class="absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded hover:bg-gray-200 text-gray-400 hover:text-gray-600"
            title="清空搜索"
          >
            <X class="w-4 h-4" />
          </button>
        </div>
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
          <button @click="loadGeneratedRules" class="btn-secondary text-sm flex items-center">
            <RefreshCw class="w-4 h-4 mr-1" />
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
                  <Check class="w-5 h-5" />
                </button>
                <button
                  @click="showGeneratedRuleDetail(rule)"
                  class="p-2 rounded-lg hover:bg-blue-100 text-blue-600"
                  title="查看详情"
                >
                  <Eye class="w-5 h-5" />
                </button>
                <button
                  @click="deleteGeneratedRule(rule.id)"
                  class="p-2 rounded-lg hover:bg-red-100 text-red-600"
                  title="删除规则"
                >
                  <Trash2 class="w-5 h-5" />
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
            <Sparkles class="w-16 h-16 mx-auto mb-4 text-gray-300" />
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
          <X class="w-5 h-5" />
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
            <p class="text-gray-700 mt-1 whitespace-pre-wrap">{{ selectedRule.description }}</p>
          </div>

          <div v-if="selectedRule.attack_scenario">
            <span class="text-sm text-gray-500">攻击场景</span>
            <div class="mt-2 p-3 bg-red-50 border border-red-100 rounded-lg">
              <p class="text-gray-700 text-sm whitespace-pre-wrap">{{ selectedRule.attack_scenario }}</p>
            </div>
          </div>

          <div v-if="selectedRule.example">
            <span class="text-sm text-gray-500">示例代码</span>
            <div class="mt-2 bg-gray-100 rounded-lg p-3 overflow-x-auto">
              <pre class="text-sm font-mono text-gray-700 whitespace-pre-wrap">{{ selectedRule.example }}</pre>
            </div>
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
import * as api from '../api'

// 使用 Lucide 图标
import {
  X,
  RefreshCw,
  Check,
  Eye,
  Trash2,
  Sparkles,
} from '../components/icons'

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
    // 安全检查：确保规则对象和必要属性存在
    if (!r) return false

    // 语言筛选
    if (filter.language && (!r.languages || !r.languages.includes(filter.language))) return false

    // 类别筛选
    if (filter.category && r.category !== filter.category) return false

    // 搜索过滤（安全访问）
    if (filter.search) {
      const search = filter.search.toLowerCase()
      const name = (r.name || '').toLowerCase()
      const description = (r.description || '').toLowerCase()
      const id = (r.id || '').toLowerCase()
      if (!name.includes(search) && !description.includes(search) && !id.includes(search)) {
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
    const [rulesResult, statsResult] = await Promise.all([
      api.listVariantRules(),
      api.getVariantStats(),
    ])

    if (rulesResult.success) {
      generatedRules.value = rulesResult.rules || rulesResult.data?.rules || []
    }
    if (statsResult.success) {
      generatedRulesStats.value = statsResult.stats || statsResult.data?.stats || {}
    }
  } catch (e) {
    console.error('Failed to load generated rules:', e)
  }
}

const approveGeneratedRule = async (ruleId) => {
  try {
    const result = await api.approveVariantRule(ruleId)
    if (result.success) {
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
    const result = await api.deleteVariantRule(ruleId)
    if (result.success) {
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
