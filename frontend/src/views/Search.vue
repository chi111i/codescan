<template>
  <div class="space-y-6 animate-fade-in">
    <!-- 页面标题 -->
    <div>
      <h1 class="text-3xl font-bold text-white">代码搜索</h1>
      <p class="text-white/60 mt-1">使用语义搜索查找相关代码</p>
    </div>

    <!-- 搜索框 -->
    <div class="glass-card rounded-2xl p-6">
      <form @submit.prevent="search" class="flex gap-4">
        <input
          v-model="query"
          type="text"
          class="input-glass flex-1"
          placeholder="输入搜索内容，例如: 用户登录验证、文件上传处理..."
        />
        <select v-model="language" class="input-glass w-40">
          <option value="">全部语言</option>
          <option value="python">Python</option>
          <option value="javascript">JavaScript</option>
          <option value="php">PHP</option>
        </select>
        <button
          type="submit"
          class="btn-primary flex items-center gap-2"
          :disabled="isSearching || !query"
        >
          <svg v-if="isSearching" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          搜索
        </button>
      </form>
    </div>

    <!-- 搜索结果 -->
    <div class="glass-card rounded-2xl p-6" v-if="results.length > 0">
      <div class="flex justify-between items-center mb-6">
        <h2 class="text-lg font-semibold text-gray-800">
          搜索结果
          <span class="text-sm font-normal text-gray-500 ml-2">{{ results.length }} 个</span>
        </h2>
      </div>

      <div class="space-y-4">
        <div
          v-for="unit in results"
          :key="unit.id"
          class="p-4 rounded-xl bg-white/30 hover:bg-white/50 transition cursor-pointer"
          @click="showCodeDetail(unit)"
        >
          <div class="flex items-start justify-between mb-3">
            <div>
              <div class="flex items-center gap-2 mb-1">
                <span class="px-2 py-0.5 text-xs bg-blue-100 text-blue-700 rounded capitalize">
                  {{ unit.language }}
                </span>
                <span class="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 rounded">
                  {{ unit.unit_type }}
                </span>
              </div>
              <h3 class="font-medium text-gray-800">{{ unit.symbol }}</h3>
              <p class="text-sm text-gray-500">{{ unit.file_path }}:{{ unit.span.start_line }}</p>
            </div>
            <div v-if="unit.parent_class" class="text-sm text-gray-500">
              类: {{ unit.parent_class }}
            </div>
          </div>

          <div v-if="unit.signature" class="text-sm text-gray-600 mb-2 font-mono">
            {{ unit.signature }}
          </div>

          <pre class="code-block text-xs max-h-32 overflow-hidden">{{ truncateCode(unit.code) }}</pre>
        </div>
      </div>
    </div>

    <!-- 空状态 -->
    <div v-else-if="hasSearched" class="glass-card rounded-2xl p-12 text-center">
      <svg class="w-16 h-16 mx-auto mb-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
      </svg>
      <h3 class="text-lg font-medium text-gray-700 mb-2">未找到相关代码</h3>
      <p class="text-gray-500">请尝试其他搜索关键词</p>
    </div>

    <!-- 代码详情弹窗 -->
    <div
      v-if="selectedUnit"
      class="fixed inset-0 z-50 flex items-center justify-center p-6"
      @click.self="selectedUnit = null"
    >
      <div class="absolute inset-0 bg-black/30 backdrop-blur-sm"></div>
      <div class="relative glass-card rounded-2xl p-6 max-w-4xl w-full max-h-[85vh] overflow-y-auto animate-slide-up">
        <button
          @click="selectedUnit = null"
          class="absolute top-4 right-4 p-2 rounded-lg hover:bg-white/30"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </button>

        <div class="space-y-6">
          <div>
            <div class="flex items-center gap-2 mb-2">
              <span class="px-2 py-1 text-sm bg-blue-100 text-blue-700 rounded capitalize">
                {{ selectedUnit.language }}
              </span>
              <span class="px-2 py-1 text-sm bg-gray-100 text-gray-600 rounded">
                {{ selectedUnit.unit_type }}
              </span>
            </div>
            <h2 class="text-xl font-bold text-gray-800">{{ selectedUnit.symbol }}</h2>
            <p class="text-sm text-gray-500 mt-1">{{ selectedUnit.file_path }}</p>
          </div>

          <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <span class="text-gray-500">行号</span>
              <p class="font-medium text-gray-800">{{ selectedUnit.span.start_line }} - {{ selectedUnit.span.end_line }}</p>
            </div>
            <div v-if="selectedUnit.parent_class">
              <span class="text-gray-500">所属类</span>
              <p class="font-medium text-gray-800">{{ selectedUnit.parent_class }}</p>
            </div>
            <div v-if="selectedUnit.decorators?.length > 0">
              <span class="text-gray-500">装饰器</span>
              <p class="font-medium text-gray-800">{{ selectedUnit.decorators.join(', ') }}</p>
            </div>
            <div v-if="selectedUnit.calls?.length > 0">
              <span class="text-gray-500">调用函数</span>
              <p class="font-medium text-gray-800">{{ selectedUnit.calls.length }} 个</p>
            </div>
          </div>

          <div v-if="selectedUnit.signature">
            <span class="text-sm text-gray-500">签名</span>
            <code class="block mt-1 px-3 py-2 bg-gray-100 rounded-lg text-sm font-mono">
              {{ selectedUnit.signature }}
            </code>
          </div>

          <div v-if="selectedUnit.docstring">
            <span class="text-sm text-gray-500">文档</span>
            <p class="text-gray-700 mt-1 whitespace-pre-wrap">{{ selectedUnit.docstring }}</p>
          </div>

          <div>
            <span class="text-sm text-gray-500">代码</span>
            <pre class="code-block mt-2">{{ selectedUnit.code }}</pre>
          </div>

          <div v-if="selectedUnit.calls?.length > 0">
            <span class="text-sm text-gray-500">调用的函数</span>
            <div class="flex flex-wrap gap-2 mt-2">
              <span
                v-for="call in selectedUnit.calls"
                :key="call"
                class="px-3 py-1 bg-white/50 rounded-lg text-sm"
              >
                {{ call }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import * as api from '../api'

const query = ref('')
const language = ref('')
const results = ref([])
const isSearching = ref(false)
const hasSearched = ref(false)
const selectedUnit = ref(null)

const truncateCode = (code, maxLines = 8) => {
  const lines = code.split('\n')
  if (lines.length <= maxLines) return code
  return lines.slice(0, maxLines).join('\n') + '\n...'
}

const showCodeDetail = (unit) => {
  selectedUnit.value = unit
}

const search = async () => {
  if (!query.value.trim()) return

  isSearching.value = true
  hasSearched.value = true

  try {
    const result = await api.searchCode({
      query: query.value,
      top_k: 20,
      language: language.value || null,
    })

    if (result.success) {
      results.value = result.data.results
    }
  } catch (error) {
    console.error('Search failed:', error)
    results.value = []
  } finally {
    isSearching.value = false
  }
}
</script>
