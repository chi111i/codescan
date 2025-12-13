<template>
  <div class="space-y-6">
    <!-- 页面标题 -->
    <div class="flex justify-between items-center">
      <div>
        <h1 class="text-3xl font-bold text-white mb-2">扫描结果</h1>
        <p class="text-white/60">查看安全扫描发现的问题</p>
      </div>
      <div class="flex gap-3">
        <select v-model="selectedScan" class="input-glass w-72">
          <option value="">选择扫描任务</option>
          <option v-for="scan in scanHistory" :key="scan.scan_id" :value="scan.scan_id">
            {{ getFileName(scan.target_path) }} - {{ formatDate(scan.started_at) }}
          </option>
        </select>
        <button @click="exportResults" class="btn-secondary flex items-center gap-2" :disabled="!scanResult">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
          </svg>
          导出报告
        </button>
      </div>
    </div>

    <!-- 有结果时显示 -->
    <template v-if="scanResult">
      <!-- 统计卡片 -->
      <div class="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div class="stat-card">
          <div class="stat-icon bg-gradient-to-br from-blue-500 to-blue-600">
            <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
            </svg>
          </div>
          <div class="stat-content">
            <div class="stat-value">{{ allFindings.length }}</div>
            <div class="stat-label">总计发现</div>
          </div>
        </div>

        <div class="stat-card" @click="filter.severity = 'critical'" :class="{ 'ring-2 ring-red-400': filter.severity === 'critical' }">
          <div class="stat-icon bg-gradient-to-br from-red-500 to-rose-600">
            <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
          </div>
          <div class="stat-content">
            <div class="stat-value text-red-600">{{ vulnStats.critical }}</div>
            <div class="stat-label">严重</div>
          </div>
        </div>

        <div class="stat-card" @click="filter.severity = 'high'" :class="{ 'ring-2 ring-orange-400': filter.severity === 'high' }">
          <div class="stat-icon bg-gradient-to-br from-orange-500 to-red-500">
            <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
          </div>
          <div class="stat-content">
            <div class="stat-value text-orange-600">{{ vulnStats.high }}</div>
            <div class="stat-label">高危</div>
          </div>
        </div>

        <div class="stat-card" @click="filter.severity = 'medium'" :class="{ 'ring-2 ring-yellow-400': filter.severity === 'medium' }">
          <div class="stat-icon bg-gradient-to-br from-yellow-500 to-orange-500">
            <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
          </div>
          <div class="stat-content">
            <div class="stat-value text-yellow-600">{{ vulnStats.medium }}</div>
            <div class="stat-label">中危</div>
          </div>
        </div>

        <div class="stat-card" @click="filter.severity = 'low'" :class="{ 'ring-2 ring-blue-400': filter.severity === 'low' }">
          <div class="stat-icon bg-gradient-to-br from-blue-400 to-cyan-500">
            <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
          </div>
          <div class="stat-content">
            <div class="stat-value text-blue-600">{{ vulnStats.low }}</div>
            <div class="stat-label">低危</div>
          </div>
        </div>
      </div>

      <!-- 主内容区 -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- 发现列表 -->
        <div class="lg:col-span-2 space-y-4">
          <!-- 过滤器栏 -->
          <div class="glass-card rounded-xl p-4">
            <div class="flex flex-wrap gap-3 items-center">
              <div class="flex items-center gap-2">
                <svg class="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"/>
                </svg>
                <span class="text-sm font-medium text-gray-700">筛选</span>
              </div>

              <select v-model="filter.category" class="input-glass text-sm py-1.5 w-36">
                <option value="">全部类型</option>
                <option v-for="cat in categories" :key="cat.value" :value="cat.value">
                  {{ cat.label }}
                </option>
              </select>

              <button
                v-if="filter.severity"
                @click="filter.severity = ''"
                class="flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium"
                :class="getSeverityClass(filter.severity)"
              >
                {{ getSeverityText(filter.severity) }}
                <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                  <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                </svg>
              </button>

              <div class="flex-1 relative">
                <svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
                <input
                  v-model="filter.search"
                  type="text"
                  class="input-glass w-full pl-9 text-sm py-1.5"
                  placeholder="搜索文件、函数、描述..."
                />
              </div>

              <button
                v-if="hasActiveFilters"
                @click="clearFilters"
                class="text-sm text-gray-500 hover:text-gray-700"
              >
                清除筛选
              </button>
            </div>
          </div>

          <!-- 发现列表 -->
          <div class="space-y-3">
            <div
              v-for="finding in filteredFindings"
              :key="finding.id"
              class="finding-card group"
              :class="{ 'ring-2 ring-blue-400': selectedFinding?.id === finding.id }"
              @click="showDetail(finding)"
            >
              <div class="flex items-start gap-4">
                <!-- 严重性指示器 -->
                <div class="flex flex-col items-center gap-1">
                  <div
                    class="w-10 h-10 rounded-xl flex items-center justify-center"
                    :class="getSeverityBgClass(finding.severity)"
                  >
                    <component :is="getSeverityIcon(finding.severity)" class="w-5 h-5" :class="getSeverityIconClass(finding.severity)" />
                  </div>
                  <span class="text-xs font-medium" :class="getSeverityTextClass(finding.severity)">
                    {{ getSeverityText(finding.severity) }}
                  </span>
                </div>

                <!-- 内容区 -->
                <div class="flex-1 min-w-0">
                  <div class="flex items-start justify-between gap-4">
                    <div class="min-w-0">
                      <h3 class="font-semibold text-gray-800 group-hover:text-blue-600 transition truncate">
                        {{ finding.title || finding.name || finding.vuln_type }}
                      </h3>
                      <div class="flex items-center gap-2 mt-1 text-sm text-gray-500">
                        <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                        </svg>
                        <span class="truncate">{{ finding.file_path }}</span>
                        <span class="shrink-0">:{{ finding.line_start }}</span>
                      </div>
                    </div>

                    <!-- 置信度 -->
                    <div class="text-right shrink-0">
                      <div class="flex items-center gap-1">
                        <div class="w-16 h-1.5 bg-gray-200 rounded-full overflow-hidden">
                          <div
                            class="h-full rounded-full transition-all"
                            :class="getConfidenceColor(finding.confidence)"
                            :style="{ width: `${finding.confidence * 100}%` }"
                          ></div>
                        </div>
                        <span class="text-sm font-medium text-gray-600">{{ Math.round(finding.confidence * 100) }}%</span>
                      </div>
                      <span class="text-xs text-gray-400">置信度</span>
                    </div>
                  </div>

                  <!-- 描述 -->
                  <p class="text-sm text-gray-600 mt-2 line-clamp-2">
                    {{ finding.summary || finding.description }}
                  </p>

                  <!-- 标签 -->
                  <div class="flex flex-wrap gap-2 mt-3">
                    <span
                      v-if="finding.category || finding.vuln_type"
                      class="px-2 py-0.5 rounded-md text-xs font-medium bg-purple-100 text-purple-700"
                    >
                      {{ finding.category || finding.vuln_type }}
                    </span>
                    <span
                      v-for="cwe in (finding.cwe_ids || []).slice(0, 2)"
                      :key="cwe"
                      class="px-2 py-0.5 rounded-md text-xs font-medium bg-indigo-100 text-indigo-700"
                    >
                      {{ cwe }}
                    </span>
                    <span
                      v-if="finding.is_taint_flow"
                      class="px-2 py-0.5 rounded-md text-xs font-medium bg-cyan-100 text-cyan-700"
                    >
                      污点流
                    </span>
                  </div>
                </div>

                <!-- 箭头 -->
                <svg class="w-5 h-5 text-gray-400 group-hover:text-blue-500 transition shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                </svg>
              </div>
            </div>

            <!-- 空状态 -->
            <div v-if="filteredFindings.length === 0" class="glass-card rounded-2xl p-12 text-center">
              <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              <h3 class="text-lg font-medium text-gray-700 mb-2">
                {{ hasActiveFilters ? '未找到匹配结果' : '暂无安全问题' }}
              </h3>
              <p class="text-gray-500">
                {{ hasActiveFilters ? '尝试调整筛选条件' : '当前扫描未发现安全问题' }}
              </p>
            </div>
          </div>
        </div>

        <!-- 详情面板 -->
        <div class="lg:col-span-1">
          <div class="glass-card rounded-2xl p-6 sticky top-6">
            <template v-if="selectedFinding">
              <!-- 标题区 -->
              <div class="flex items-start justify-between mb-6">
                <div>
                  <span
                    class="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium"
                    :class="getSeverityClass(selectedFinding.severity)"
                  >
                    <component :is="getSeverityIcon(selectedFinding.severity)" class="w-3.5 h-3.5" />
                    {{ getSeverityText(selectedFinding.severity) }}
                  </span>
                  <h2 class="text-lg font-bold text-gray-800 mt-3 leading-tight">
                    {{ selectedFinding.title || selectedFinding.name || selectedFinding.vuln_type }}
                  </h2>
                </div>
                <button @click="selectedFinding = null" class="p-1.5 rounded-lg hover:bg-gray-100 transition">
                  <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                  </svg>
                </button>
              </div>

              <!-- 选项卡 -->
              <div class="flex border-b border-gray-200 mb-4">
                <button
                  v-for="tab in detailTabs"
                  :key="tab.key"
                  @click="activeTab = tab.key"
                  class="px-4 py-2 text-sm font-medium border-b-2 -mb-px transition"
                  :class="activeTab === tab.key
                    ? 'text-blue-600 border-blue-600'
                    : 'text-gray-500 border-transparent hover:text-gray-700'"
                >
                  {{ tab.label }}
                </button>
              </div>

              <!-- 详情内容 -->
              <div class="detail-content">
                <!-- 概览选项卡 -->
                <div v-show="activeTab === 'overview'" class="space-y-4">
                  <div class="grid grid-cols-2 gap-3 text-sm">
                    <div class="p-3 rounded-lg bg-gray-50">
                      <div class="text-gray-500 text-xs mb-1">文件位置</div>
                      <div class="font-medium text-gray-800 truncate" :title="selectedFinding.file_path">
                        {{ getFileName(selectedFinding.file_path) }}
                      </div>
                    </div>
                    <div class="p-3 rounded-lg bg-gray-50">
                      <div class="text-gray-500 text-xs mb-1">行号范围</div>
                      <div class="font-medium text-gray-800">
                        {{ selectedFinding.line_start }} - {{ selectedFinding.line_end || selectedFinding.line_start }}
                      </div>
                    </div>
                    <div class="p-3 rounded-lg bg-gray-50">
                      <div class="text-gray-500 text-xs mb-1">置信度</div>
                      <div class="flex items-center gap-2">
                        <div class="flex-1 h-1.5 bg-gray-200 rounded-full overflow-hidden">
                          <div
                            class="h-full rounded-full"
                            :class="getConfidenceColor(selectedFinding.confidence)"
                            :style="{ width: `${selectedFinding.confidence * 100}%` }"
                          ></div>
                        </div>
                        <span class="font-medium text-gray-800">{{ Math.round(selectedFinding.confidence * 100) }}%</span>
                      </div>
                    </div>
                    <div class="p-3 rounded-lg bg-gray-50">
                      <div class="text-gray-500 text-xs mb-1">漏洞类型</div>
                      <div class="font-medium text-gray-800">
                        {{ selectedFinding.category || selectedFinding.vuln_type || '-' }}
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 class="text-sm font-medium text-gray-700 mb-2">问题描述</h4>
                    <p class="text-sm text-gray-600 leading-relaxed">
                      {{ selectedFinding.summary || selectedFinding.description }}
                    </p>
                  </div>

                  <div v-if="selectedFinding.cwe_ids?.length">
                    <h4 class="text-sm font-medium text-gray-700 mb-2">相关标准</h4>
                    <div class="flex flex-wrap gap-2">
                      <a
                        v-for="cwe in selectedFinding.cwe_ids"
                        :key="cwe"
                        :href="`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`"
                        target="_blank"
                        class="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-indigo-100 text-indigo-700 hover:bg-indigo-200 transition"
                      >
                        {{ cwe }}
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                        </svg>
                      </a>
                    </div>
                  </div>
                </div>

                <!-- 代码选项卡 -->
                <div v-show="activeTab === 'code'" class="space-y-4">
                  <div v-if="selectedFinding.code_snippet">
                    <h4 class="text-sm font-medium text-gray-700 mb-2">问题代码</h4>
                    <pre class="code-block text-xs overflow-x-auto"><code>{{ selectedFinding.code_snippet }}</code></pre>
                  </div>

                  <div v-if="selectedFinding.evidence?.length">
                    <h4 class="text-sm font-medium text-gray-700 mb-2">证据链</h4>
                    <div class="space-y-2">
                      <div
                        v-for="(ev, idx) in selectedFinding.evidence"
                        :key="idx"
                        class="p-3 rounded-lg bg-gray-50 text-sm"
                      >
                        <div class="font-medium text-gray-700 mb-1">{{ ev.type || '证据' }} {{ idx + 1 }}</div>
                        <pre class="text-xs text-gray-600 whitespace-pre-wrap">{{ ev.content || ev }}</pre>
                      </div>
                    </div>
                  </div>

                  <div v-if="!selectedFinding.code_snippet && !selectedFinding.evidence?.length" class="text-center py-8 text-gray-500">
                    <svg class="w-12 h-12 mx-auto mb-2 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
                    </svg>
                    暂无代码片段
                  </div>
                </div>

                <!-- 分析选项卡 -->
                <div v-show="activeTab === 'analysis'" class="space-y-4">
                  <div v-if="selectedFinding.details">
                    <h4 class="text-sm font-medium text-gray-700 mb-2">详细分析</h4>
                    <div class="text-sm text-gray-600 whitespace-pre-wrap leading-relaxed">{{ selectedFinding.details }}</div>
                  </div>

                  <div v-if="selectedFinding.attack_scenario">
                    <h4 class="text-sm font-medium text-gray-700 mb-2">攻击场景</h4>
                    <div class="p-3 rounded-lg bg-red-50 border border-red-100">
                      <p class="text-sm text-red-800 whitespace-pre-wrap">{{ selectedFinding.attack_scenario }}</p>
                    </div>
                  </div>

                  <!-- 污点流可视化 -->
                  <div v-if="selectedFinding.taint_path?.length">
                    <h4 class="text-sm font-medium text-gray-700 mb-2">数据流追踪</h4>
                    <div class="taint-flow">
                      <div
                        v-for="(step, idx) in selectedFinding.taint_path"
                        :key="idx"
                        class="taint-step"
                      >
                        <div class="taint-node" :class="getTaintNodeClass(idx, selectedFinding.taint_path.length)">
                          <span class="taint-label">{{ getTaintLabel(idx, selectedFinding.taint_path.length) }}</span>
                        </div>
                        <div class="taint-content">
                          <code class="text-xs">{{ step }}</code>
                        </div>
                        <div v-if="idx < selectedFinding.taint_path.length - 1" class="taint-arrow">
                          <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 14l-7 7m0 0l-7-7m7 7V3"/>
                          </svg>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div v-if="!selectedFinding.details && !selectedFinding.attack_scenario && !selectedFinding.taint_path?.length" class="text-center py-8 text-gray-500">
                    <svg class="w-12 h-12 mx-auto mb-2 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
                    </svg>
                    暂无详细分析
                  </div>
                </div>

                <!-- 修复选项卡 -->
                <div v-show="activeTab === 'fix'" class="space-y-4">
                  <div v-if="selectedFinding.fix_suggestion">
                    <h4 class="text-sm font-medium text-gray-700 mb-2">修复建议</h4>
                    <div class="p-3 rounded-lg bg-green-50 border border-green-100">
                      <p class="text-sm text-green-800 whitespace-pre-wrap">{{ selectedFinding.fix_suggestion }}</p>
                    </div>
                  </div>

                  <div v-if="selectedFinding.notes">
                    <h4 class="text-sm font-medium text-gray-700 mb-2">备注说明</h4>
                    <div class="p-3 rounded-lg bg-yellow-50 border border-yellow-100">
                      <p class="text-sm text-yellow-800 whitespace-pre-wrap">{{ selectedFinding.notes }}</p>
                    </div>
                  </div>

                  <div v-if="!selectedFinding.fix_suggestion && !selectedFinding.notes" class="text-center py-8 text-gray-500">
                    <svg class="w-12 h-12 mx-auto mb-2 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    暂无修复建议
                  </div>
                </div>
              </div>
            </template>

            <!-- 未选择状态 -->
            <template v-else>
              <div class="text-center py-12">
                <div class="w-20 h-20 mx-auto mb-4 rounded-full bg-gray-100 flex items-center justify-center">
                  <svg class="w-10 h-10 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122"/>
                  </svg>
                </div>
                <h3 class="text-lg font-medium text-gray-700 mb-2">选择一个发现</h3>
                <p class="text-sm text-gray-500">点击左侧列表查看详细信息</p>
              </div>
            </template>
          </div>
        </div>
      </div>
    </template>

    <!-- 空状态 -->
    <div v-else class="glass-card rounded-2xl p-12 text-center">
      <div class="w-24 h-24 mx-auto mb-6 rounded-full bg-gradient-to-br from-gray-100 to-gray-200 flex items-center justify-center">
        <svg class="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
        </svg>
      </div>
      <h3 class="text-xl font-semibold text-gray-700 mb-2">暂无扫描结果</h3>
      <p class="text-gray-500 mb-6">请选择已完成的扫描任务或执行新的代码安全扫描</p>
      <router-link to="/scan" class="btn-primary inline-flex items-center gap-2">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
        </svg>
        开始扫描
      </router-link>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted, h } from 'vue'
import { useRoute } from 'vue-router'
import { useAppStore } from '../stores/app'
import * as api from '../api'

const route = useRoute()
const appStore = useAppStore()

const selectedScan = ref('')
const scanResult = ref(null)
const selectedFinding = ref(null)
const activeTab = ref('overview')

const filter = reactive({
  severity: '',
  category: '',
  search: '',
})

const detailTabs = [
  { key: 'overview', label: '概览' },
  { key: 'code', label: '代码' },
  { key: 'analysis', label: '分析' },
  { key: 'fix', label: '修复' },
]

const categories = [
  { value: 'rce', label: 'RCE' },
  { value: 'command_injection', label: '命令注入' },
  { value: 'sql_injection', label: 'SQL注入' },
  { value: 'file_read', label: '文件读取' },
  { value: 'file_write', label: '文件写入' },
  { value: 'ssrf', label: 'SSRF' },
  { value: 'ssti', label: 'SSTI' },
  { value: 'deserialization', label: '反序列化' },
  { value: 'auth_bypass', label: '认证绕过' },
  { value: 'idor', label: 'IDOR' },
  { value: 'logic_flaw', label: '逻辑漏洞' },
]

const scanHistory = computed(() => appStore.scanHistory)

const allFindings = computed(() => {
  if (!scanResult.value) return []
  return [
    ...(scanResult.value.findings || []).map(f => ({ ...f, id: f.id || `f-${Math.random()}` })),
    ...(scanResult.value.vuln_findings || []).map(f => ({ ...f, id: f.id || `v-${Math.random()}` })),
    ...(scanResult.value.taint_flows || []).map(f => ({
      ...f,
      id: f.id || `t-${Math.random()}`,
      is_taint_flow: true,
      title: `污点流: ${f.source} → ${f.sink}`,
      file_path: f.sink_location?.split(':')[0] || '',
      line_start: f.sink_location?.split(':')[1] || 0,
      severity: f.risk_level?.toLowerCase() || 'medium',
      taint_path: f.path,
    })),
  ]
})

const filteredFindings = computed(() => {
  return allFindings.value.filter(f => {
    if (filter.severity && f.severity !== filter.severity) return false
    if (filter.category) {
      const cat = (f.category || f.vuln_type || '').toLowerCase()
      if (!cat.includes(filter.category)) return false
    }
    if (filter.search) {
      const search = filter.search.toLowerCase()
      const title = (f.title || f.name || '').toLowerCase()
      const file = (f.file_path || '').toLowerCase()
      const desc = (f.summary || f.description || '').toLowerCase()
      const symbol = (f.symbol || '').toLowerCase()
      if (!title.includes(search) && !file.includes(search) && !desc.includes(search) && !symbol.includes(search)) {
        return false
      }
    }
    return true
  })
})

const vulnStats = computed(() => {
  const stats = { critical: 0, high: 0, medium: 0, low: 0 }
  allFindings.value.forEach(f => {
    const sev = f.severity?.toLowerCase()
    if (sev in stats) stats[sev]++
  })
  return stats
})

const hasActiveFilters = computed(() => {
  return filter.severity || filter.category || filter.search
})

const clearFilters = () => {
  filter.severity = ''
  filter.category = ''
  filter.search = ''
}

// 严重性相关函数
const getSeverityClass = (severity) => {
  const classes = {
    critical: 'bg-red-100 text-red-700',
    high: 'bg-orange-100 text-orange-700',
    medium: 'bg-yellow-100 text-yellow-700',
    low: 'bg-blue-100 text-blue-700',
    info: 'bg-gray-100 text-gray-700',
  }
  return classes[severity] || classes.info
}

const getSeverityBgClass = (severity) => {
  const classes = {
    critical: 'bg-red-100',
    high: 'bg-orange-100',
    medium: 'bg-yellow-100',
    low: 'bg-blue-100',
  }
  return classes[severity] || 'bg-gray-100'
}

const getSeverityIconClass = (severity) => {
  const classes = {
    critical: 'text-red-600',
    high: 'text-orange-600',
    medium: 'text-yellow-600',
    low: 'text-blue-600',
  }
  return classes[severity] || 'text-gray-600'
}

const getSeverityTextClass = (severity) => {
  const classes = {
    critical: 'text-red-600',
    high: 'text-orange-600',
    medium: 'text-yellow-600',
    low: 'text-blue-600',
  }
  return classes[severity] || 'text-gray-600'
}

const getSeverityText = (severity) => {
  const texts = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  }
  return texts[severity] || severity
}

// 严重性图标
const CriticalIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z' })
  ])
}

const HighIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' })
  ])
}

const MediumIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z' })
  ])
}

const LowIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z' })
  ])
}

const getSeverityIcon = (severity) => {
  const icons = {
    critical: CriticalIcon,
    high: HighIcon,
    medium: MediumIcon,
    low: LowIcon,
  }
  return icons[severity] || LowIcon
}

const getConfidenceColor = (confidence) => {
  if (confidence >= 0.8) return 'bg-green-500'
  if (confidence >= 0.6) return 'bg-yellow-500'
  return 'bg-orange-500'
}

const getTaintNodeClass = (idx, total) => {
  if (idx === 0) return 'bg-red-500 text-white'
  if (idx === total - 1) return 'bg-purple-500 text-white'
  return 'bg-blue-500 text-white'
}

const getTaintLabel = (idx, total) => {
  if (idx === 0) return 'Source'
  if (idx === total - 1) return 'Sink'
  return `Step ${idx}`
}

const getFileName = (path) => {
  if (!path) return '未知'
  const parts = path.split(/[/\\]/)
  return parts[parts.length - 1] || parts[parts.length - 2] || path
}

const formatDate = (dateStr) => {
  if (!dateStr) return ''
  const date = new Date(dateStr)
  return date.toLocaleString('zh-CN', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

const showDetail = (finding) => {
  selectedFinding.value = finding
  activeTab.value = 'overview'
}

const exportResults = () => {
  if (!scanResult.value) return

  const exportData = {
    scan_id: selectedScan.value,
    exported_at: new Date().toISOString(),
    summary: {
      total: allFindings.value.length,
      ...vulnStats.value,
    },
    findings: allFindings.value,
  }

  const data = JSON.stringify(exportData, null, 2)
  const blob = new Blob([data], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `scan_report_${selectedScan.value}_${new Date().toISOString().split('T')[0]}.json`
  a.click()
  URL.revokeObjectURL(url)
}

const loadScanResult = async (scanId) => {
  if (!scanId) {
    scanResult.value = null
    selectedFinding.value = null
    return
  }
  try {
    const result = await api.getScanResult(scanId)
    if (result.success) {
      scanResult.value = result.data
      selectedFinding.value = null
    }
  } catch (error) {
    console.error('Load scan result failed:', error)
  }
}

watch(selectedScan, loadScanResult)

// 处理 URL 参数中的 severity 筛选
watch(() => route.query.severity, (severity) => {
  if (severity) {
    filter.severity = severity
  }
}, { immediate: true })

onMounted(async () => {
  await appStore.fetchScanHistory()

  if (route.params.scanId) {
    selectedScan.value = route.params.scanId
  } else if (scanHistory.value.length > 0) {
    selectedScan.value = scanHistory.value[0].scan_id
  }
})
</script>

<style scoped>
.stat-card {
  @apply glass-card rounded-xl p-4 flex items-center gap-4 cursor-pointer transition-all;
}

.stat-card:hover {
  @apply bg-white/70;
  transform: translateY(-2px);
}

.stat-icon {
  @apply w-12 h-12 rounded-xl flex items-center justify-center shrink-0;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.stat-content {
  @apply flex-1 min-w-0;
}

.stat-value {
  @apply text-2xl font-bold text-gray-800;
}

.stat-label {
  @apply text-sm text-gray-500;
}

.finding-card {
  @apply glass-card rounded-xl p-4 cursor-pointer transition-all;
}

.finding-card:hover {
  @apply bg-white/70;
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
}

.line-clamp-2 {
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.detail-content {
  @apply max-h-[calc(100vh-400px)] overflow-y-auto pr-2;
}

.detail-content::-webkit-scrollbar {
  width: 4px;
}

.detail-content::-webkit-scrollbar-track {
  background: transparent;
}

.detail-content::-webkit-scrollbar-thumb {
  background: rgba(0, 0, 0, 0.1);
  border-radius: 2px;
}

/* 污点流样式 */
.taint-flow {
  @apply space-y-2;
}

.taint-step {
  @apply flex items-start gap-3;
}

.taint-node {
  @apply w-16 h-6 rounded-md flex items-center justify-center shrink-0;
}

.taint-label {
  @apply text-xs font-medium;
}

.taint-content {
  @apply flex-1 p-2 rounded-lg bg-gray-50 overflow-x-auto;
}

.taint-arrow {
  @apply flex justify-center py-1;
}
</style>
