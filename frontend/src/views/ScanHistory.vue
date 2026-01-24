<template>
  <div class="h-[calc(100vh-3rem)] flex flex-col">
    <!-- 页面标题 -->
    <div class="flex items-center justify-between mb-6 shrink-0">
      <div>
        <h1 class="text-2xl font-semibold text-gray-900 mb-1 flex items-center gap-3">
          <svg class="w-8 h-8 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          扫描记录
        </h1>
        <p class="text-gray-500 text-sm">查看深度扫描的历史记录和结果</p>
      </div>

      <div class="flex items-center gap-3">
        <!-- 搜索框 -->
        <div class="relative">
          <input
            v-model="searchQuery"
            type="text"
            class="input-glass pl-10 pr-8 py-2 w-64"
            placeholder="搜索扫描记录..."
          />
          <svg class="w-5 h-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          <!-- 搜索清空按钮 -->
          <button
            v-if="searchQuery"
            @click="searchQuery = ''"
            class="absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded hover:bg-gray-200 text-gray-400 hover:text-gray-600"
            title="清空搜索"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>

        <!-- 状态筛选 -->
        <select v-model="statusFilter" class="input-glass py-2 pr-8">
          <option value="">全部状态</option>
          <option value="pending">进行中</option>
          <option value="completed">已完成</option>
          <option value="failed">失败</option>
        </select>

        <!-- 刷新按钮 -->
        <button
          @click="fetchScans"
          class="btn-secondary p-2"
          :disabled="isLoading"
        >
          <svg
            class="w-5 h-5"
            :class="{ 'animate-spin': isLoading }"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
          </svg>
        </button>
      </div>
    </div>

    <!-- 统计卡片 -->
    <div class="grid grid-cols-4 gap-4 mb-6 shrink-0">
      <div class="glass-card rounded-xl p-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
            </svg>
          </div>
          <div>
            <div class="text-2xl font-bold text-gray-800">{{ stats.total }}</div>
            <div class="text-xs text-gray-500">总扫描数</div>
          </div>
        </div>
      </div>

      <div class="glass-card rounded-xl p-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-green-500 to-green-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
            </svg>
          </div>
          <div>
            <div class="text-2xl font-bold text-gray-800">{{ stats.completed }}</div>
            <div class="text-xs text-gray-500">已完成</div>
          </div>
        </div>
      </div>

      <div class="glass-card rounded-xl p-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-red-500 to-red-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
          </div>
          <div>
            <div class="text-2xl font-bold text-gray-800">{{ formatNumber(stats.totalFindings) }}</div>
            <div class="text-xs text-gray-500">发现数</div>
          </div>
        </div>
      </div>

      <div class="glass-card rounded-xl p-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-orange-500 to-orange-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
          </div>
          <div>
            <div class="text-2xl font-bold text-gray-800">{{ stats.pending }}</div>
            <div class="text-xs text-gray-500">进行中</div>
          </div>
        </div>
      </div>
    </div>

    <!-- 扫描列表 -->
    <div class="flex-1 overflow-hidden">
      <div class="glass-card rounded-2xl p-4 h-full flex flex-col">
        <!-- 加载状态：仅在首次加载（无数据时）显示全屏加载 -->
        <div v-if="isLoading && scans.length === 0" class="flex-1 flex items-center justify-center">
          <div class="text-center">
            <svg class="w-12 h-12 mx-auto mb-4 text-emerald-500 spinner" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <p class="text-gray-500">加载中...</p>
          </div>
        </div>

        <!-- 空状态 -->
        <div v-else-if="!isLoading && filteredScans.length === 0" class="flex-1 flex items-center justify-center">
          <div class="text-center">
            <svg class="w-20 h-20 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
            </svg>
            <p class="text-lg font-medium text-gray-500 mb-2">暂无扫描记录</p>
            <p class="text-sm text-gray-400 mb-4">开始一个新的安全扫描</p>
            <router-link to="/audit" class="btn-primary inline-flex items-center gap-2">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
              </svg>
              开始智能审计
            </router-link>
          </div>
        </div>

        <!-- 扫描列表 -->
        <div v-else class="flex-1 overflow-y-auto space-y-3 dark-scroll">
          <div
            v-for="scan in filteredScans"
            :key="scan.id"
            class="scan-card p-4 rounded-xl cursor-pointer transition-all duration-200"
            @click="viewScan(scan)"
          >
            <div class="flex items-start justify-between">
              <div class="flex-1 min-w-0">
                <!-- 标题和状态 -->
                <div class="flex items-center gap-2 mb-1">
                  <h3 class="font-medium text-gray-800 truncate">
                    扫描 #{{ scan.id?.slice(0, 8) || 'N/A' }}
                  </h3>
                  <span
                    class="px-2 py-0.5 rounded-full text-xs shrink-0"
                    :class="getStatusBadgeClass(scan.status)"
                  >
                    {{ getStatusText(scan.status) }}
                  </span>
                  <!-- 严重性标签 -->
                  <span
                    v-if="scan.critical_count > 0"
                    class="severity-badge severity-critical"
                  >
                    {{ scan.critical_count }} 严重
                  </span>
                  <span
                    v-if="scan.high_count > 0"
                    class="severity-badge severity-high"
                  >
                    {{ scan.high_count }} 高危
                  </span>
                </div>

                <!-- 目标路径 -->
                <p class="text-sm text-gray-500 truncate mb-2">
                  <svg class="w-4 h-4 inline-block mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                  </svg>
                  {{ scan.target_path || '未指定路径' }}
                </p>

                <!-- 统计信息 -->
                <div class="flex items-center gap-4 text-xs text-gray-400">
                  <span class="flex items-center gap-1">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                    </svg>
                    {{ scan.findings_count || 0 }} 个发现
                  </span>
                  <span class="flex items-center gap-1">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
                    </svg>
                    {{ getLanguageDisplay(scan) }}
                  </span>
                  <span class="flex items-center gap-1">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    {{ formatDate(scan.created_at) }}
                  </span>
                  <!-- 进度条 (仅进行中显示) -->
                  <span v-if="scan.status === 'pending'" class="flex items-center gap-2 flex-1 max-w-32">
                    <div class="progress-bar flex-1 h-1.5">
                      <div class="progress-bar-fill" :style="{ width: `${(scan.progress || 0) * 100}%` }"></div>
                    </div>
                    <span>{{ Math.round((scan.progress || 0) * 100) }}%</span>
                  </span>
                </div>
              </div>

              <!-- 操作按钮 -->
              <div class="flex items-center gap-2 ml-4">
                <button
                  @click.stop="viewScanDetail(scan)"
                  class="btn-primary text-sm px-3 py-1.5"
                >
                  <span class="flex items-center gap-1">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                    </svg>
                    查看
                  </span>
                </button>
                <button
                  @click.stop="rescan(scan)"
                  class="btn-secondary text-sm px-3 py-1.5"
                  title="重新扫描"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                  </svg>
                </button>
                <button
                  @click.stop="deleteScan(scan)"
                  class="btn-secondary text-red-500 hover:bg-red-50 p-1.5"
                  title="删除记录"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- 分页 -->
        <div v-if="totalPages > 1" class="mt-4 flex items-center justify-center gap-2 shrink-0">
          <button
            @click="currentPage--"
            :disabled="currentPage <= 1"
            class="btn-secondary px-3 py-1.5 text-sm"
          >
            上一页
          </button>
          <span class="text-sm text-gray-500">
            第 {{ currentPage }} / {{ totalPages }} 页
          </span>
          <button
            @click="currentPage++"
            :disabled="currentPage >= totalPages"
            class="btn-secondary px-3 py-1.5 text-sm"
          >
            下一页
          </button>
        </div>
      </div>
    </div>

    <!-- 扫描详情弹窗 -->
    <teleport to="body">
      <transition name="fade">
        <div v-if="showDetailModal" class="modal-overlay" @click.self="closeDetailModal">
          <div class="modal-content max-w-6xl w-[90vw] p-6">
            <div class="flex items-center justify-between mb-6">
              <h2 class="text-xl font-bold text-gray-800">扫描详情</h2>
              <button @click="closeDetailModal" class="btn-icon">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
              </button>
            </div>

            <div v-if="selectedScanDetail" class="space-y-4">
              <!-- 基本信息 -->
              <div class="glass-subtle p-4 rounded-xl">
                <h3 class="font-medium text-gray-700 mb-3">基本信息</h3>
                <div class="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span class="text-gray-500">扫描 ID：</span>
                    <span class="text-gray-800 font-mono">{{ selectedScanDetail.id }}</span>
                  </div>
                  <div>
                    <span class="text-gray-500">状态：</span>
                    <span :class="getStatusBadgeClass(selectedScanDetail.status)" class="px-2 py-0.5 rounded-full text-xs">
                      {{ getStatusText(selectedScanDetail.status) }}
                    </span>
                  </div>
                  <div>
                    <span class="text-gray-500">目标路径：</span>
                    <span class="text-gray-800">{{ selectedScanDetail.target_path }}</span>
                  </div>
                  <div>
                    <span class="text-gray-500">语言：</span>
                    <span class="text-gray-800">{{ getLanguageDisplay(selectedScanDetail) }}</span>
                  </div>
                  <div>
                    <span class="text-gray-500">创建时间：</span>
                    <span class="text-gray-800">{{ formatFullDate(selectedScanDetail.created_at) }}</span>
                  </div>
                  <div>
                    <span class="text-gray-500">完成时间：</span>
                    <span class="text-gray-800">{{ selectedScanDetail.completed_at ? formatFullDate(selectedScanDetail.completed_at) : '-' }}</span>
                  </div>
                </div>
              </div>

              <!-- 发现统计 -->
              <div class="glass-subtle p-4 rounded-xl">
                <h3 class="font-medium text-gray-700 mb-3">发现统计</h3>
                <div class="flex items-center gap-4">
                  <div class="flex items-center gap-2">
                    <span class="severity-badge severity-critical">严重</span>
                    <span class="text-lg font-bold">{{ selectedScanDetail.critical_count || 0 }}</span>
                  </div>
                  <div class="flex items-center gap-2">
                    <span class="severity-badge severity-high">高危</span>
                    <span class="text-lg font-bold">{{ selectedScanDetail.high_count || 0 }}</span>
                  </div>
                  <div class="flex items-center gap-2">
                    <span class="severity-badge severity-medium">中危</span>
                    <span class="text-lg font-bold">{{ selectedScanDetail.medium_count || 0 }}</span>
                  </div>
                  <div class="flex items-center gap-2">
                    <span class="severity-badge severity-low">低危</span>
                    <span class="text-lg font-bold">{{ selectedScanDetail.low_count || 0 }}</span>
                  </div>
                </div>
              </div>

              <!-- 发现列表 -->
              <div v-if="selectedScanFindings.length > 0" class="glass-subtle p-4 rounded-xl">
                <h3 class="font-medium text-gray-700 mb-3">发现列表 ({{ selectedScanFindings.length }})</h3>
                <div class="max-h-96 overflow-y-auto space-y-3 dark-scroll">
                  <div
                    v-for="finding in selectedScanFindings"
                    :key="finding.id"
                    class="p-4 bg-white/50 rounded-lg cursor-pointer hover:bg-white/70 hover:shadow-sm transition-all border border-gray-100"
                    @click="viewFindingDetail(finding)"
                  >
                    <div class="flex items-start justify-between">
                      <div class="flex-1 min-w-0">
                        <!-- 标题行：严重级别 + 漏洞类型 + 置信度 -->
                        <div class="flex items-center gap-2 mb-2 flex-wrap">
                          <span :class="getSeverityBadgeClass(finding.severity)" class="severity-badge">
                            {{ getSeverityLabel(finding.severity) }}
                          </span>
                          <span class="font-medium text-gray-800">
                            {{ finding.vuln_type || finding.category || finding.title || finding.name || finding.issue_type || finding.type || '未知类型' }}
                          </span>
                          <span v-if="finding.confidence" class="text-xs px-1.5 py-0.5 rounded bg-gray-100 text-gray-600">
                            置信度: {{ Math.round((finding.confidence || 0) * 100) }}%
                          </span>
                        </div>

                        <!-- 摘要/描述 -->
                        <p v-if="finding.summary || finding.description" class="text-sm text-gray-600 mb-2">
                          {{ finding.summary || finding.description }}
                        </p>

                        <!-- 详细信息 -->
                        <div v-if="finding.details" class="text-sm text-gray-500 mb-2 line-clamp-2">
                          {{ finding.details }}
                        </div>

                        <!-- 攻击场景预览 -->
                        <div v-if="finding.attack_scenario" class="text-xs bg-red-50 text-red-700 px-2 py-1 rounded mb-2 line-clamp-2">
                          <span class="font-medium">攻击场景：</span>{{ finding.attack_scenario }}
                        </div>

                        <!-- 修复建议预览 -->
                        <div v-if="finding.fix_suggestion" class="text-xs bg-green-50 text-green-700 px-2 py-1 rounded mb-2 line-clamp-2">
                          <span class="font-medium">修复建议：</span>{{ finding.fix_suggestion }}
                        </div>

                        <!-- 代码位置 + CWE -->
                        <div class="flex items-center gap-3 text-xs text-gray-400 flex-wrap">
                          <span class="flex items-center gap-1">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                            </svg>
                            {{ truncatePath(finding.file_path) }}:{{ finding.line_start }}
                          </span>
                          <span v-if="finding.symbol" class="flex items-center gap-1">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
                            </svg>
                            {{ finding.symbol }}
                          </span>
                          <span v-if="finding.cwe_ids && finding.cwe_ids.length > 0" class="text-orange-600">
                            {{ Array.isArray(finding.cwe_ids) ? finding.cwe_ids.join(', ') : finding.cwe_ids }}
                          </span>
                        </div>
                      </div>
                      <svg class="w-5 h-5 text-gray-400 shrink-0 ml-3 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                      </svg>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </transition>
    </teleport>

    <!-- 漏洞详情弹窗 -->
    <FindingDetailModal
      :visible="showFindingDetailModal"
      :finding="selectedFinding"
      @close="closeFindingDetailModal"
    />
  </div>
</template>

<script setup>
// 组件名称 - 用于 keep-alive 缓存匹配
defineOptions({ name: 'ScanHistory' })

import { ref, computed, onMounted, onActivated, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import * as api from '../api'
import FindingDetailModal from '../components/FindingDetailModal.vue'

const router = useRouter()
const route = useRoute()

// 状态
const scans = ref([])
const isLoading = ref(false)
const searchQuery = ref('')
const statusFilter = ref('')
const currentPage = ref(1)
const pageSize = 20
const totalCount = ref(0)

// 请求节流控制
let lastFetchTime = 0
const FETCH_THROTTLE_MS = 2000 // 2秒内不重复请求

// 弹窗状态
const showDetailModal = ref(false)
const selectedScanDetail = ref(null)
const selectedScanFindings = ref([])

// 漏洞详情弹窗状态
const showFindingDetailModal = ref(false)
const selectedFinding = ref(null)

// 统计
const stats = computed(() => {
  const total = scans.value.length
  const completed = scans.value.filter(s => s.status === 'completed').length
  const pending = scans.value.filter(s => s.status === 'pending').length
  const totalFindings = scans.value.reduce((sum, s) => sum + (s.findings_count || 0), 0)
  return { total, completed, pending, totalFindings }
})

// 过滤后的扫描列表
const filteredScans = computed(() => {
  let result = scans.value

  // 状态过滤
  if (statusFilter.value) {
    result = result.filter(s => s && s.status === statusFilter.value)
  }

  // 搜索过滤（安全访问）
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    result = result.filter(s => {
      if (!s) return false
      const id = (s.id || '').toLowerCase()
      const targetPath = (s.target_path || '').toLowerCase()
      const language = (s.language || '').toLowerCase()
      return id.includes(query) || targetPath.includes(query) || language.includes(query)
    })
  }

  return result
})

// 总页数
const totalPages = computed(() => Math.ceil(filteredScans.value.length / pageSize))

// 方法
const fetchScans = async (force = false) => {
  // 节流：2秒内不重复请求（除非强制刷新）
  const now = Date.now()
  if (!force && now - lastFetchTime < FETCH_THROTTLE_MS && scans.value.length > 0) {
    return
  }
  lastFetchTime = now

  isLoading.value = true
  try {
    const result = await api.listScans()
    // API 返回格式: { success: true, data: { tasks: [...], total, limit, offset } }
    if (result.success && result.data?.tasks) {
      // 将 scan_id 映射为 id，以及其他字段映射
      scans.value = result.data.tasks.map(task => ({
        id: task.scan_id,
        status: task.status,
        target_path: task.target_path,
        created_at: task.started_at,
        completed_at: task.completed_at,
        findings_count: task.findings_count || 0,
        vuln_count: task.vuln_count || 0,
        progress: task.progress,
        language: task.language,
        critical_count: task.critical_count || 0,
        high_count: task.high_count || 0,
        medium_count: task.medium_count || 0,
        low_count: task.low_count || 0,
      }))
      totalCount.value = result.data.total || scans.value.length
    } else if (result && result.scans) {
      // 兼容旧格式
      scans.value = result.scans || []
      totalCount.value = result.scans.length
    } else if (Array.isArray(result)) {
      scans.value = result
      totalCount.value = result.length
    }
  } catch (error) {
    console.error('获取扫描列表失败:', error)
  } finally {
    isLoading.value = false
  }
}

const viewScan = (scan) => {
  viewScanDetail(scan)
}

const viewScanDetail = async (scan) => {
  showDetailModal.value = true
  selectedScanDetail.value = scan
  selectedScanFindings.value = []

  try {
    const result = await api.getScanFindings(scan.id)
    // API 返回格式: { success: true, data: { findings: [...], vuln_findings: [...] } }
    if (result && result.success && result.data) {
      // 合并 findings 和 vuln_findings
      const findings = result.data.findings || []
      const vulnFindings = result.data.vuln_findings || []
      selectedScanFindings.value = [...findings, ...vulnFindings]
    } else if (result && result.findings) {
      // 兼容旧格式
      const findings = result.findings || []
      const vulnFindings = result.vuln_findings || []
      selectedScanFindings.value = [...findings, ...vulnFindings]
    } else if (Array.isArray(result)) {
      selectedScanFindings.value = result
    }
  } catch (error) {
    console.error('获取扫描发现失败:', error)
  }
}

const closeDetailModal = () => {
  showDetailModal.value = false
  selectedScanDetail.value = null
  selectedScanFindings.value = []
}

// 显示漏洞详情
const viewFindingDetail = (finding) => {
  selectedFinding.value = finding
  showFindingDetailModal.value = true
}

// 关闭漏洞详情
const closeFindingDetailModal = () => {
  showFindingDetailModal.value = false
  selectedFinding.value = null
}

const rescan = async (scan) => {
  if (!confirm('确定要重新扫描该目标吗？')) {
    return
  }

  try {
    await api.startScan({
      target_path: scan.target_path,
      language: scan.language,
    })
    await fetchScans()
  } catch (error) {
    console.error('启动扫描失败:', error)
    alert('启动扫描失败')
  }
}

const deleteScan = async (scan) => {
  if (!confirm(`确定要删除扫描记录 #${scan.id?.slice(0, 8)} 吗？`)) {
    return
  }

  try {
    await api.deleteScan(scan.id)
    scans.value = scans.value.filter(s => s.id !== scan.id)
    totalCount.value--
  } catch (error) {
    console.error('删除扫描失败:', error)
    alert('删除扫描失败')
  }
}

const getStatusBadgeClass = (status) => {
  const classes = {
    pending: 'bg-yellow-100 text-yellow-700',
    completed: 'bg-green-100 text-green-700',
    failed: 'bg-red-100 text-red-700',
  }
  return classes[status] || 'bg-gray-100 text-gray-600'
}

const getStatusText = (status) => {
  const texts = {
    pending: '进行中',
    completed: '已完成',
    failed: '失败',
  }
  return texts[status] || status
}

const getSeverityBadgeClass = (severity) => {
  const classes = {
    critical: 'severity-critical',
    high: 'severity-high',
    medium: 'severity-medium',
    low: 'severity-low',
    info: 'severity-info',
  }
  return classes[severity?.toLowerCase()] || 'severity-info'
}

// 获取严重级别标签
const getSeverityLabel = (severity) => {
  const labels = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  }
  return labels[severity?.toLowerCase()] || severity || '未知'
}

// 截断路径显示
const truncatePath = (path) => {
  if (!path) return ''
  const parts = path.split(/[/\\]/)
  if (parts.length <= 2) return path
  return '.../' + parts.slice(-2).join('/')
}

// 获取语言显示文本
const getLanguageDisplay = (scan) => {
  if (!scan) return '未知'
  // 优先从 config.languages 数组获取
  const languages = scan.config?.languages || scan.languages
  if (languages && Array.isArray(languages) && languages.length > 0) {
    return languages.join(', ')
  }
  // 回退到 language 字段
  if (scan.language) {
    return scan.language
  }
  // 尝试从目标路径推断语言
  const targetPath = scan.target_path || ''
  if (targetPath.includes('.php') || targetPath.toLowerCase().includes('php')) {
    return 'PHP'
  }
  if (targetPath.includes('.py') || targetPath.toLowerCase().includes('python')) {
    return 'Python'
  }
  if (targetPath.includes('.js') || targetPath.toLowerCase().includes('javascript')) {
    return 'JavaScript'
  }
  return '自动检测'
}

const formatDate = (dateStr) => {
  if (!dateStr) return '-'
  const date = new Date(dateStr)
  const now = new Date()
  const diff = now - date

  // 小于 1 小时
  if (diff < 3600000) {
    const minutes = Math.floor(diff / 60000)
    return minutes <= 0 ? '刚刚' : `${minutes} 分钟前`
  }
  // 小于 24 小时
  if (diff < 86400000) {
    const hours = Math.floor(diff / 3600000)
    return `${hours} 小时前`
  }
  // 小于 7 天
  if (diff < 604800000) {
    const days = Math.floor(diff / 86400000)
    return `${days} 天前`
  }
  // 其他
  return date.toLocaleDateString('zh-CN', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

const formatFullDate = (dateStr) => {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleString('zh-CN')
}

const formatNumber = (num) => {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}

// 监听筛选条件变化
watch([statusFilter], () => {
  currentPage.value = 1
})

// 生命周期
onMounted(async () => {
  await fetchScans(true) // 首次加载强制请求
  // 检查是否有 scan_id 查询参数，如果有则自动打开详情
  const scanId = route.query.scan_id
  if (scanId) {
    const targetScan = scans.value.find(s => s.scan_id === scanId || s.id === scanId)
    if (targetScan) {
      viewScanDetail(targetScan)
    }
  }
})

// keep-alive 激活时重新获取数据（带节流，避免频繁切换时卡顿）
onActivated(() => {
  fetchScans() // 使用节流，2秒内不重复请求
})
</script>

<style scoped>
.scan-card {
  background: rgba(255, 255, 255, 0.5);
  border: 1px solid rgba(255, 255, 255, 0.3);
}

.scan-card:hover {
  background: rgba(255, 255, 255, 0.7);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
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

/* 模态框过渡 */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
