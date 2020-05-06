<template>
  <div class="home">
    Home. {{ key }}
    <br />
    <v-button id="download_link" download="keypair.txt" href=""> Download keypair as text file</v-button>
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
  mounted: function() {
    var text = "Public Key: 43242344 \nSecret Key: 20348932805";
    var data = new Blob([text], { type: "text/plain" });

    var url = window.URL.createObjectURL(data);

    document.getElementById("download_link").href = url;
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