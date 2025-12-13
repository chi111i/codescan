<template>
  <div class="space-y-6 animate-fade-in">
    <!-- 页面标题 -->
    <div class="flex justify-between items-center">
      <div>
        <h1 class="text-3xl font-bold text-white">调用链分析</h1>
        <p class="text-white/60 mt-1">分析函数调用关系和污点传播路径</p>
      </div>
      <button
        @click="runAnalysis"
        class="btn-primary flex items-center gap-2"
        :disabled="isAnalyzing"
      >
        <svg v-if="isAnalyzing" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        {{ isAnalyzing ? '分析中...' : '开始分析' }}
      </button>
    </div>

    <!-- 统计卡片 -->
    <div class="grid grid-cols-2 md:grid-cols-6 gap-4" v-if="analysisResult">
      <div class="glass-card rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-gray-800">{{ analysisResult.stats.total_nodes }}</div>
        <div class="text-xs text-gray-500">节点数</div>
      </div>
      <div class="glass-card rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-gray-800">{{ analysisResult.stats.total_edges }}</div>
        <div class="text-xs text-gray-500">边数</div>
      </div>
      <div class="glass-card rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-blue-600">{{ analysisResult.stats.entry_points }}</div>
        <div class="text-xs text-gray-500">入口点</div>
      </div>
      <div class="glass-card rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-green-600">{{ analysisResult.stats.sources }}</div>
        <div class="text-xs text-gray-500">输入源</div>
      </div>
      <div class="glass-card rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-red-600">{{ analysisResult.stats.sinks }}</div>
        <div class="text-xs text-gray-500">危险函数</div>
      </div>
      <div class="glass-card rounded-xl p-4 text-center">
        <div class="text-2xl font-bold text-purple-600">{{ analysisResult.stats.sanitizers }}</div>
        <div class="text-xs text-gray-500">过滤函数</div>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6" v-if="analysisResult">
      <!-- 污点路径 -->
      <div class="glass-card rounded-2xl p-6">
        <h2 class="text-lg font-semibold text-gray-800 mb-4">
          污点传播路径
          <span class="text-sm font-normal text-gray-500 ml-2">
            {{ analysisResult.taint_paths.length }} 条
          </span>
        </h2>

        <div class="space-y-3 max-h-[500px] overflow-y-auto">
          <div
            v-for="(path, idx) in analysisResult.taint_paths"
            :key="idx"
            class="p-4 rounded-xl transition cursor-pointer"
            :class="path.is_sanitized ? 'bg-green-50 hover:bg-green-100' : 'bg-red-50 hover:bg-red-100'"
            @click="showPathDetail(path)"
          >
            <div class="flex items-center justify-between mb-2">
              <span
                class="px-2 py-1 rounded text-xs font-medium"
                :class="path.is_sanitized ? 'bg-green-200 text-green-800' : 'bg-red-200 text-red-800'"
              >
                {{ path.is_sanitized ? '已过滤' : '未过滤' }}
              </span>
              <span class="text-sm text-gray-500">
                置信度: {{ Math.round(path.confidence * 100) }}%
              </span>
            </div>

            <div class="flex items-center gap-2 text-sm">
              <span class="text-green-700 font-medium truncate max-w-[120px]">{{ path.source_node }}</span>
              <svg class="w-4 h-4 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 8l4 4m0 0l-4 4m4-4H3"/>
              </svg>
              <span class="text-red-700 font-medium truncate max-w-[120px]">{{ path.sink_node }}</span>
            </div>

            <p class="text-xs text-gray-500 mt-2 truncate">{{ path.description }}</p>
          </div>

          <div v-if="analysisResult.taint_paths.length === 0" class="text-center py-8 text-gray-500">
            未发现污点传播路径
          </div>
        </div>
      </div>

      <!-- 危险调用链 -->
      <div class="glass-card rounded-2xl p-6">
        <h2 class="text-lg font-semibold text-gray-800 mb-4">
          危险调用链
          <span class="text-sm font-normal text-gray-500 ml-2">
            {{ analysisResult.dangerous_chains.length }} 条
          </span>
        </h2>

        <div class="space-y-3 max-h-[500px] overflow-y-auto">
          <div
            v-for="(chain, idx) in analysisResult.dangerous_chains"
            :key="idx"
            class="p-4 rounded-xl bg-white/30 hover:bg-white/50 transition"
          >
            <div class="flex items-center justify-between mb-2">
              <span
                class="px-2 py-1 rounded text-xs font-medium"
                :class="getRiskClass(chain.effective_risk)"
              >
                {{ chain.effective_risk }}
              </span>
              <span class="text-xs text-gray-500">
                长度: {{ chain.chain_length }}
              </span>
            </div>

            <div class="text-sm text-gray-700 mb-2">
              <span class="font-medium">{{ chain.entry_point }}</span>
              <span class="text-gray-400 mx-2">→</span>
              <span class="text-red-600 font-medium">{{ chain.sink_function }}</span>
            </div>

            <div v-if="chain.chain && chain.chain.length > 0" class="flex flex-wrap gap-1">
              <span
                v-for="(node, i) in chain.chain.slice(0, 5)"
                :key="i"
                class="px-2 py-0.5 text-xs bg-white/50 rounded"
              >
                {{ node }}
              </span>
              <span v-if="chain.chain.length > 5" class="text-xs text-gray-400">
                +{{ chain.chain.length - 5 }} more
              </span>
            </div>
          </div>

          <div v-if="analysisResult.dangerous_chains.length === 0" class="text-center py-8 text-gray-500">
            未发现危险调用链
          </div>
        </div>
      </div>
    </div>

    <!-- 空状态 -->
    <div v-if="!analysisResult" class="glass-card rounded-2xl p-12 text-center">
      <svg class="w-20 h-20 mx-auto mb-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>
      </svg>
      <h3 class="text-lg font-medium text-gray-700 mb-2">开始调用链分析</h3>
      <p class="text-gray-500 mb-6">分析函数调用关系，发现潜在的安全风险路径</p>
    </div>

    <!-- 路径详情弹窗 -->
    <div
      v-if="selectedPath"
      class="fixed inset-0 z-50 flex items-center justify-center p-6"
      @click.self="selectedPath = null"
    >
      <div class="absolute inset-0 bg-black/30 backdrop-blur-sm"></div>
      <div class="relative glass-card rounded-2xl p-6 max-w-2xl w-full animate-slide-up">
        <button
          @click="selectedPath = null"
          class="absolute top-4 right-4 p-2 rounded-lg hover:bg-white/30"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </button>

        <h2 class="text-xl font-bold text-gray-800 mb-6">污点路径详情</h2>

        <div class="space-y-4">
          <div class="grid grid-cols-2 gap-4">
            <div>
              <span class="text-sm text-gray-500">输入源</span>
              <p class="font-medium text-green-700">{{ selectedPath.source_node }}</p>
            </div>
            <div>
              <span class="text-sm text-gray-500">危险函数</span>
              <p class="font-medium text-red-700">{{ selectedPath.sink_node }}</p>
            </div>
          </div>

          <div>
            <span class="text-sm text-gray-500">完整路径</span>
            <div class="flex flex-wrap items-center gap-2 mt-2">
              <span
                v-for="(node, idx) in selectedPath.path"
                :key="idx"
                class="flex items-center gap-2"
              >
                <span class="px-3 py-1 bg-white/50 rounded-lg text-sm">{{ node }}</span>
                <svg v-if="idx < selectedPath.path.length - 1" class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                </svg>
              </span>
            </div>
          </div>

          <div v-if="selectedPath.sanitizers?.length > 0">
            <span class="text-sm text-gray-500">过滤函数</span>
            <div class="flex flex-wrap gap-2 mt-2">
              <span
                v-for="s in selectedPath.sanitizers"
                :key="s"
                class="px-3 py-1 bg-purple-100 text-purple-700 rounded-lg text-sm"
              >
                {{ s }}
              </span>
            </div>
          </div>

          <div>
            <span class="text-sm text-gray-500">描述</span>
            <p class="text-gray-700 mt-1">{{ selectedPath.description }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useAppStore } from '../stores/app'
import * as api from '../api'

const appStore = useAppStore()

const isAnalyzing = ref(false)
const analysisResult = ref(null)
const selectedPath = ref(null)

const getRiskClass = (risk) => {
  const classes = {
    critical: 'bg-red-200 text-red-800',
    high: 'bg-orange-200 text-orange-800',
    medium: 'bg-yellow-200 text-yellow-800',
    low: 'bg-blue-200 text-blue-800',
  }
  return classes[risk] || 'bg-gray-200 text-gray-800'
}

const showPathDetail = (path) => {
  selectedPath.value = path
}

const runAnalysis = async () => {
  isAnalyzing.value = true

  try {
    // 先获取统计信息确定目标路径
    const stats = appStore.stats

    const result = await api.analyzeCallGraph({
      target_path: '.',  // 使用当前已索引的项目
      max_depth: 10,
      find_taint: true,
    })

    if (result.success) {
      analysisResult.value = result.data
    }
  } catch (error) {
    console.error('Analysis failed:', error)
    alert('分析失败: ' + error.message)
  } finally {
    isAnalyzing.value = false
  }
}
</script>
