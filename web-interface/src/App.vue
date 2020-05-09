<template>
  <div class="home">
    Home. {{ key }}
  </div>
</template>

<script>
import axios from "axios";
export default {
  name: "home",
  data() {
    return {
      key: "key not yet updated."
    };
  },
  created: function() {
    axios
      .get("http://127.0.0.1:5000/key")
      .then(response => {
        console.log(response);
        this.key = response.data;
      })
      .catch(error => console.log(error));
  }
};
</script>