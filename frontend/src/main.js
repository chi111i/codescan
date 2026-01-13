import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import './style.css'

// 路由配置
const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: () => import('./views/Dashboard.vue'),
    meta: { keepAlive: true },
  },
  {
    path: '/audit',
    name: 'UnifiedAudit',
    component: () => import('./views/UnifiedAudit.vue'),
    meta: { keepAlive: true },
  },
  {
    // 兼容性重定向：/scan 重定向到 /audit
    path: '/scan',
    redirect: '/audit',
  },
  {
    path: '/interactive',
    name: 'InteractiveAudit',
    component: () => import('./views/InteractiveAudit.vue'),
  },
  {
    path: '/chat-history',
    name: 'ChatHistory',
    component: () => import('./views/ChatHistory.vue'),
    meta: { keepAlive: true },
  },
  {
    path: '/scan-history',
    name: 'ScanHistory',
    component: () => import('./views/ScanHistory.vue'),
    meta: { keepAlive: true },
  },
  {
    path: '/callgraph',
    name: 'CallGraph',
    component: () => import('./views/CallGraph.vue'),
  },
  {
    path: '/code-graph',
    name: 'CodeGraph',
    component: () => import('./views/CodeGraph.vue'),
  },
  {
    path: '/variant-analysis',
    name: 'VariantAnalysis',
    component: () => import('./views/VariantAnalysis.vue'),
  },
  {
    path: '/rules',
    name: 'Rules',
    component: () => import('./views/Rules.vue'),
  },
  {
    path: '/search',
    name: 'Search',
    component: () => import('./views/Search.vue'),
  },
  {
    path: '/settings',
    name: 'Settings',
    component: () => import('./views/Settings.vue'),
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.mount('#app')
