import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.levelace.levarg',
  appName: 'LevarG',
  webDir: 'dist',
  plugins: {
    CapacitorNodeJS: {
      nodeDir: 'nodejs',
    },
    SplashScreen: {
      launchShowDuration: 2000,
      launchAutoHide: true,
      backgroundColor: '#050505',
      showSpinner: true,
      spinnerColor: '#10b981',
      androidScaleType: 'CENTER_CROP',
    },
    StatusBar: {
      backgroundColor: '#050505',
      style: 'DARK',
    },
    LocalNotifications: {
      smallIcon: 'ic_stat_levarg',
      iconColor: '#10b981',
    },
  },
  server: {
    androidScheme: 'https',
  },
};

export default config;
