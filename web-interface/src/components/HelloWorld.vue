<template>
  <div class="home">
    <v-file-input chips label="Attach public keys .PEM file" @change="onAddPublicKeys" accept=".pem"></v-file-input>
    <v-text-field
      prepend-icon="mdi-format-list-numbered"
      label="Index of your public key within the public keys file"
      v-model="index"
    ></v-text-field>
    <v-file-input chips label="Attach private key .PEM file" @change="onAddSecretKey" accept=".pem"></v-file-input>
    <v-text-field prepend-icon="mdi-key" label="Enter password used for private key file" type="password" v-model="password"></v-text-field>
    <v-text-field prepend-icon="mdi-text" label="Enter message to leak" v-model="message"></v-text-field>
    <v-btn v-on:click="submitData()" color="primary">Submit</v-btn>
    <h3>Don't have any key pairs? Run the following commands:</h3>
    <br />
    <v-timeline dense>
      <v-timeline-item>
        <v-card class="elevation-2">
          <v-card-title class="headline">generate encrypted key pair:</v-card-title>
          <v-card-text>$openssl genrsa -out [FILENAME].pem -aes128 -passout pass:[PASSWORD] 2048</v-card-text>
        </v-card>
      </v-timeline-item>
      <v-timeline-item>
        <v-card class="elevation-2">
          <v-card-title class="headline">extract public key:</v-card-title>
          <v-card-text>$openssl rsa -in [FILENAME].pem -pubout -out [filename1].pem</v-card-text>
        </v-card>
      </v-timeline-item>
    </v-timeline>
    Index: {{ index }}
    Message: {{ message }}
    Key: {{ key }}
    <br />
    <a id="download_link" download="keypair.txt" href>Download keypair as text file</a>
  </div>
</template>

<script>
import axios from "axios";
export default {
  name: "home",
  data() {
    return {
      key: "key not yet updated.",
      pksFile: "",
      skFile: "",
      index: "",
      message: "",
      password: ""
    };
  },
  methods: {
    onAddSecretKey(file) {
      window.console.log(file);
      this.skFile = file;
      let formData = new FormData();
      // add files to form data
      formData.append("files", file, file.name);
      axios
        .post("http://127.0.0.1:5000/secret_key", formData)
        .then(response => {
          console.log("Uploaded secret key!");
          console.log({ response });
        })
    },
    onAddPublicKeys(file) {
      window.console.log(file);
      this.skFile = file;
      let formData = new FormData();
      // add files to form data
      formData.append("files", file, file.name);
      axios
        .post("http://127.0.0.1:5000/public_keys", formData)
        .then(response => {
          console.log("Uploaded public keys!");
          console.log({ response });
        })
    },
    submitData() {
      let formData = new FormData();

      // add index and message to form data
      formData.append("index", this.index);
      formData.append("message", this.message);
      formData.append("password", this.password);

      // additional data
      formData.append("test", "foo bar");

      axios
        .post("http://127.0.0.1:5000/signature", formData)
        .then(response => {
          console.log("Success!");
          console.log({ response });
        })
        .catch(error => {
          console.log({ error });
        });
    }
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