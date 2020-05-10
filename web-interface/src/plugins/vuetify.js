import Vue from 'vue';
import Vuetify from 'vuetify';
import 'vuetify/dist/vuetify.min.css';

Vue.use(Vuetify);

export default new Vuetify({
  theme: {
    themes: {
      light: {
        primary: '#009688',
        secondary: '#e91e63',
        accent: '#2196f3',
        error: '#f44336',
        warning: '#ff5722',
        info: '#4caf50',
        success: '#8bc34a'
      },
    },
  },
});
