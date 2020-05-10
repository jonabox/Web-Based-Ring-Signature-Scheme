<template>
  <v-app>
    <v-app-bar
      app
      color="primary"
      dark
    >
      <div class="d-flex align-center">
        <h3>
          Web Based Ring Signature Scheme
        </h3>
      </div>

      <v-spacer></v-spacer>

      <v-btn
        href="https://github.com/jonabox/Web-Based-Ring-Signature-Scheme"
        target="_blank"
        text
      >
        <span class="mr-2">View Project on GitHub</span>
        <v-icon>mdi-open-in-new</v-icon>
      </v-btn>
    </v-app-bar>

    <v-content>
      <HelloWorld/>
    </v-content>
  </v-app>
</template>

<script>
import HelloWorld from './components/HelloWorld';

export default {
  name: 'App',

  components: {
    HelloWorld,
  },

  data: () => ({
    //
  }),
};
</script>
