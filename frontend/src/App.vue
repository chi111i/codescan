<template>
  <div class="min-h-screen flex">
    <!-- 侧边栏 -->
    <Sidebar />

    <!-- 主内容区 -->
    <main class="flex-1 p-6 ml-64">
      <router-view v-slot="{ Component }">
        <transition name="fade" mode="out-in">
          <component :is="Component" />
        </transition>
      </router-view>
    </main>
  </div>
</template>

<script setup>
import Sidebar from './components/Sidebar.vue'
</script>
