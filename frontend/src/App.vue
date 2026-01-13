<template>
  <div class="min-h-screen flex">
    <!-- 侧边栏 -->
    <Sidebar />

    <!-- 主内容区 -->
    <main class="flex-1 p-6 ml-64">
      <router-view v-slot="{ Component, route }">
        <!--
          临时移除 transition 以诊断问题
          使用 :include 动态控制缓存
        -->
        <keep-alive :include="cachedViews">
          <component :is="Component" :key="route.path" />
        </keep-alive>
      </router-view>
    </main>
  </div>
</template>

<script setup>
import { computed, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuditStore } from './stores/auditStore'
import Sidebar from './components/Sidebar.vue'

const router = useRouter()
const auditStore = useAuditStore()

// 定义需要缓存的视图组件名称列表
// 基于 router 配置中 meta.keepAlive 的路由
const cachedViews = computed(() => {
  return router.getRoutes()
    .filter(route => route.meta?.keepAlive)
    .map(route => route.name)
    .filter(Boolean)
})

// 路由切换时清理资源（WebSocket、HTTP 请求等）
// 修复：调用完整的 cleanup() 而不仅仅是 cancelPendingRequest()
// 这确保 WebSocket 连接被立即关闭，不会阻塞 UI
router.beforeEach((to, from, next) => {
  // 仅在实际页面切换时清理（不是初始加载）
  if (from.name && to.name !== from.name) {
    auditStore.cleanup()
  }
  next()
})

// 页面卸载时清理资源
onUnmounted(() => {
  auditStore.cleanup()
})
</script>

<style>
/* 页面切换过渡动画 - Apple 风格 */
.page-fade-enter-active,
.page-fade-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.page-fade-enter-from {
  opacity: 0;
  transform: translateY(8px);
}

.page-fade-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}
</style>
