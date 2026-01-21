<template>
  <div class="scan-config-panel space-y-6">
    <!-- 目标路径 -->
    <div>
      <label class="block text-sm font-medium text-gray-700 mb-2">
        <span class="flex items-center gap-2">
          <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
          </svg>
          目标路径
        </span>
      </label>
      <div class="flex gap-3">
        <input
          v-model="config.targetPath"
          type="text"
          class="input-glass flex-1"
          placeholder="输入项目路径，例如: /path/to/project"
        />
      </div>
    </div>

    <!-- 语言选择 -->
    <div>
      <label class="block text-sm font-medium text-gray-700 mb-3">
        <span class="flex items-center gap-2">
          <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
          </svg>
          扫描语言
        </span>
      </label>
      <div class="flex flex-wrap gap-3">
        <label
          v-for="lang in availableLanguages"
          :key="lang.value"
          class="lang-chip group"
          :class="{ active: config.languages.includes(lang.value) }"
        >
          <input
            type="checkbox"
            :value="lang.value"
            v-model="config.languages"
            class="hidden"
          />
          <span class="lang-icon" :class="lang.iconClass">{{ lang.icon }}</span>
          <span>{{ lang.label }}</span>
          <svg v-if="config.languages.includes(lang.value)" class="w-4 h-4 text-blue-600" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
          </svg>
        </label>
      </div>
    </div>

    <!-- 漏洞类型 -->
    <div>
      <label class="block text-sm font-medium text-gray-700 mb-3">
        <span class="flex items-center gap-2">
          <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
          </svg>
          漏洞类型
        </span>
      </label>
      <div class="flex flex-wrap gap-2">
        <label
          v-for="vt in vulnTypes"
          :key="vt.value"
          class="vuln-chip"
          :class="{ active: config.vulnTypes.includes(vt.value) }"
        >
          <input
            type="checkbox"
            :value="vt.value"
            v-model="config.vulnTypes"
            class="hidden"
          />
          <span class="vuln-dot" :class="vt.colorClass"></span>
          <span>{{ vt.label }}</span>
        </label>
      </div>
      <div class="flex gap-2 mt-3">
        <button type="button" @click="selectAllVulnTypes" class="text-xs text-blue-600 hover:text-blue-700">
          全选
        </button>
        <span class="text-gray-300">|</span>
        <button type="button" @click="clearVulnTypes" class="text-xs text-gray-500 hover:text-gray-700">
          清空
        </button>
      </div>
    </div>

    <!-- 高级选项 -->
    <div class="space-y-4">
      <div class="flex items-center justify-between">
        <label class="text-sm font-medium text-gray-700 flex items-center gap-2">
          <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/>
          </svg>
          高级选项
        </label>
        <button
          type="button"
          @click="showAdvanced = !showAdvanced"
          class="text-sm text-blue-600 hover:text-blue-700"
        >
          {{ showAdvanced ? '收起' : '展开' }}
        </button>
      </div>

      <transition name="slide">
        <div v-if="showAdvanced" class="grid grid-cols-2 gap-4">
          <label class="option-card">
            <input type="checkbox" v-model="config.useLLM" class="hidden" />
            <div class="option-checkbox" :class="{ checked: config.useLLM }">
              <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
              </svg>
            </div>
            <div>
              <span class="text-sm font-medium text-gray-800">LLM 深度分析</span>
              <p class="text-xs text-gray-500">使用 AI 进行深度漏洞验证</p>
            </div>
          </label>

          <label class="option-card">
            <input type="checkbox" v-model="config.scanLogic" class="hidden" />
            <div class="option-checkbox" :class="{ checked: config.scanLogic }">
              <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
              </svg>
            </div>
            <div>
              <span class="text-sm font-medium text-gray-800">业务逻辑扫描</span>
              <p class="text-xs text-gray-500">检测权限、流程等逻辑漏洞</p>
            </div>
          </label>

          <label class="option-card">
            <input type="checkbox" v-model="config.useChainAnalysis" class="hidden" />
            <div class="option-checkbox" :class="{ checked: config.useChainAnalysis }">
              <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
              </svg>
            </div>
            <div>
              <span class="text-sm font-medium text-gray-800">链级分析（推荐）</span>
              <p class="text-xs text-gray-500">追踪调用链 + 污点传播</p>
            </div>
          </label>

          <label class="option-card">
            <input type="checkbox" v-model="config.skipIndex" class="hidden" />
            <div class="option-checkbox" :class="{ checked: config.skipIndex }">
              <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
              </svg>
            </div>
            <div>
              <span class="text-sm font-medium text-gray-800">跳过向量索引</span>
              <p class="text-xs text-gray-500">小项目推荐，速度更快</p>
            </div>
          </label>

          <!-- P2-1: 多阶段验证选项 -->
          <label class="option-card">
            <input type="checkbox" v-model="config.enableTriage" class="hidden" />
            <div class="option-checkbox" :class="{ checked: config.enableTriage }">
              <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
              </svg>
            </div>
            <div>
              <span class="text-sm font-medium text-gray-800">Triage 快筛</span>
              <p class="text-xs text-gray-500">快速过滤明显误报</p>
            </div>
          </label>

          <label class="option-card">
            <input type="checkbox" v-model="config.enableDeepVerify" class="hidden" />
            <div class="option-checkbox" :class="{ checked: config.enableDeepVerify }">
              <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
              </svg>
            </div>
            <div>
              <span class="text-sm font-medium text-gray-800">深度验证</span>
              <p class="text-xs text-gray-500">使用强模型深度分析</p>
            </div>
          </label>

          <label class="option-card">
            <input type="checkbox" v-model="config.enableDeterministicValidation" class="hidden" />
            <div class="option-checkbox" :class="{ checked: config.enableDeterministicValidation }">
              <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
              </svg>
            </div>
            <div>
              <span class="text-sm font-medium text-gray-800">确定性验证</span>
              <p class="text-xs text-gray-500">校验行号/路径防幻觉</p>
            </div>
          </label>

          <div class="col-span-2 grid grid-cols-2 gap-4">
            <div class="p-4 rounded-xl bg-white/30">
              <label class="text-sm font-medium text-gray-700 block mb-2">最大分析数</label>
              <input
                type="number"
                v-model="config.maxIssues"
                min="10"
                max="200"
                class="w-full px-3 py-2 rounded-lg bg-white/50 border border-white/30 outline-none focus:border-blue-400"
              />
            </div>
            <div class="p-4 rounded-xl bg-white/30">
              <label class="text-sm font-medium text-gray-700 block mb-2">调用链深度</label>
              <input
                type="number"
                v-model="config.maxChainDepth"
                min="1"
                max="15"
                class="w-full px-3 py-2 rounded-lg bg-white/50 border border-white/30 outline-none focus:border-blue-400"
              />
            </div>
          </div>
        </div>
      </transition>
    </div>

    <!-- 操作按钮 -->
    <div class="flex justify-end gap-4 pt-4 border-t border-gray-200/50">
      <button type="button" class="btn-secondary" @click="resetConfig">
        重置配置
      </button>
      <button
        type="button"
        class="btn-primary flex items-center gap-2"
        :disabled="isScanning || !config.targetPath"
        @click="handleStartScan"
      >
        <svg v-if="isScanning" class="w-5 h-5 spinner" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
        </svg>
        <span>{{ isScanning ? '扫描中...' : '开始扫描' }}</span>
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, defineEmits, defineProps } from 'vue'

const props = defineProps({
  isScanning: {
    type: Boolean,
    default: false
  }
})

const emit = defineEmits(['start-scan', 'config-change'])

const showAdvanced = ref(false)

const config = reactive({
  targetPath: '',
  languages: [],
  vulnTypes: ['rce', 'command_injection', 'sql_injection'],
  useLLM: true,
  scanLogic: true,
  useChainAnalysis: true,
  reindex: false,
  skipIndex: false,
  maxIssues: 50,
  maxChainDepth: 5,
  // P2-1: 多阶段验证配置
  enableTriage: true,
  enableDeepVerify: true,
  enableDeterministicValidation: true,
})

const availableLanguages = [
  { value: 'python', label: 'Python', icon: '🐍', iconClass: 'bg-yellow-100' },
  { value: 'javascript', label: 'JavaScript', icon: '⚡', iconClass: 'bg-yellow-100' },
  { value: 'typescript', label: 'TypeScript', icon: '💠', iconClass: 'bg-blue-100' },
  { value: 'php', label: 'PHP', icon: '🐘', iconClass: 'bg-purple-100' },
]

const vulnTypes = [
  { value: 'rce', label: 'RCE', colorClass: 'bg-red-500' },
  { value: 'command_injection', label: '命令注入', colorClass: 'bg-red-400' },
  { value: 'sql_injection', label: 'SQL注入', colorClass: 'bg-orange-500' },
  { value: 'file_read', label: '文件读取', colorClass: 'bg-yellow-500' },
  { value: 'file_write', label: '文件写入', colorClass: 'bg-yellow-600' },
  { value: 'ssrf', label: 'SSRF', colorClass: 'bg-purple-500' },
  { value: 'ssti', label: 'SSTI', colorClass: 'bg-pink-500' },
  { value: 'deserialization', label: '反序列化', colorClass: 'bg-indigo-500' },
  { value: 'auth_bypass', label: '认证绕过', colorClass: 'bg-blue-500' },
  { value: 'idor', label: 'IDOR', colorClass: 'bg-cyan-500' },
  { value: 'logic_flaw', label: '逻辑漏洞', colorClass: 'bg-teal-500' },
]

const selectAllVulnTypes = () => {
  config.vulnTypes = vulnTypes.map(v => v.value)
}

const clearVulnTypes = () => {
  config.vulnTypes = []
}

const resetConfig = () => {
  config.targetPath = ''
  config.languages = []
  config.vulnTypes = ['rce', 'command_injection', 'sql_injection']
  config.useLLM = true
  config.scanLogic = true
  config.useChainAnalysis = true
  config.reindex = false
  config.skipIndex = false
  config.maxIssues = 50
  config.maxChainDepth = 5
}

const handleStartScan = () => {
  if (!config.targetPath) {
    alert('请输入目标路径')
    return
  }
  emit('start-scan', {
    target_path: config.targetPath,
    languages: config.languages.length > 0 ? config.languages : null,
    vuln_types: config.vulnTypes.length > 0 ? config.vulnTypes : null,
    use_llm: config.useLLM,
    scan_logic: config.scanLogic,
    use_chain_analysis: config.useChainAnalysis,
    reindex: config.reindex,
    skip_index: config.skipIndex,
    max_issues: config.maxIssues,
    max_chain_depth: config.maxChainDepth,
  })
}

// 暴露配置供父组件使用
defineExpose({
  config,
  resetConfig,
})
</script>

<style scoped>
.lang-chip {
  @apply flex items-center gap-2 px-4 py-2.5 rounded-xl bg-white/50 border border-white/30 cursor-pointer transition-all duration-300;
}

.lang-chip:hover {
  @apply bg-white/70 border-blue-200;
}

.lang-chip.active {
  @apply bg-blue-50 border-blue-300 ring-2 ring-blue-100;
}

.lang-icon {
  @apply w-7 h-7 rounded-lg flex items-center justify-center text-sm;
}

.vuln-chip {
  @apply flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/40 border border-white/20 cursor-pointer text-sm transition-all duration-200;
}

.vuln-chip:hover {
  @apply bg-white/60;
}

.vuln-chip.active {
  @apply bg-white/70 border-gray-300 shadow-sm;
}

.vuln-dot {
  @apply w-2 h-2 rounded-full;
}

.option-card {
  @apply flex items-start gap-3 p-4 rounded-xl bg-white/40 border border-white/20 cursor-pointer transition-all duration-200;
}

.option-card:hover {
  @apply bg-white/60;
}

.option-checkbox {
  @apply w-5 h-5 rounded-md border-2 border-gray-300 flex items-center justify-center text-white transition-all duration-200 flex-shrink-0 mt-0.5;
}

.option-checkbox.checked {
  @apply bg-blue-500 border-blue-500;
}

.slide-enter-active,
.slide-leave-active {
  transition: all 0.3s ease;
}

.slide-enter-from,
.slide-leave-to {
  opacity: 0;
  max-height: 0;
}

.slide-enter-to,
.slide-leave-from {
  opacity: 1;
  max-height: 500px;
}

.spinner {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
</style>
