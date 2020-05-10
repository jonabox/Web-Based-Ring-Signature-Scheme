<template>
  <div class="home">
    <v-tabs v-model="tab" background-color="transparent" grow>
      <v-tab>Sign</v-tab>
      <v-tab>Verify</v-tab>
      <v-tab>Generate Key Pairs</v-tab>
    </v-tabs>
    <v-tabs-items v-model="tab">
      <v-tab-item>
        <v-card flat>
          <v-file-input
            chips
            label="Attach public keys .PEM file"
            @change="onAddPublicKeys"
            accept=".pem"
          ></v-file-input>
          <v-text-field
            prepend-icon="mdi-format-list-numbered"
            label="Index of your public key within the public keys file"
            v-model="index"
          ></v-text-field>
          <v-file-input
            chips
            label="Attach private key .PEM file"
            @change="onAddSecretKey"
            accept=".pem"
          ></v-file-input>
          <v-text-field
            prepend-icon="mdi-key"
            label="Enter password used for private key file"
            type="password"
            v-model="password"
          ></v-text-field>
          <v-text-field prepend-icon="mdi-text" label="Enter message to leak" v-model="message"></v-text-field>
          <v-btn v-on:click="submitDataSign()" color="primary">Submit</v-btn>
        </v-card>
      </v-tab-item>
      <v-tab-item>
        <v-alert
          v-if="displayVerified"
          text
          color="primary"
          type="success"
        >The message is associated with this ring signature.</v-alert>
        <v-alert
          v-if="displayNotVerified"
          text
          color="error"
          type="error"
        >The message is not associated with this ring signature.</v-alert>
        <v-card flat>
          <v-file-input
            chips
            label="Attach signature .PEM file"
            @change="onAddSignature"
            accept=".pem"
          ></v-file-input>
          <v-text-field prepend-icon="mdi-text" label="Enter leaked message" v-model="message"></v-text-field>
          <v-btn v-on:click="submitDataVerify()" color="primary">Submit</v-btn>
        </v-card>
      </v-tab-item>
      <v-tab-item>
        <h3 class="font-weight-regular">Don't have any key pairs? Run the following commands:</h3>
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
      </v-tab-item>
    </v-tabs-items>
    <br />
  </div>
</template>

<script>
import axios from "axios";
export default {
  name: "home",
  data() {
    return {
      tab: null,
      key: "key not yet updated.",
      pksFile: "",
      skFile: "",
      signatureFile: "",
      index: "",
      message: "",
      password: "",
      displayVerified: false,
      displayNotVerified: false
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
        });
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
        });
    },
    onAddSignature(file) {
      window.console.log(file);
      this.signatureFile = file;
      let formData = new FormData();
      // add files to form data
      formData.append("files", file, file.name);
      axios
        .post("http://127.0.0.1:5000/signature_file", formData)
        .then(response => {
          console.log("Uploaded signature file!");
          console.log({ response });
        });
    },
    submitDataSign() {
      let formData = new FormData();

      // add index and message to form data
      formData.append("index", this.index);
      formData.append("message", this.message);
      formData.append("password", this.password);

      axios
        .post("http://127.0.0.1:5000/signature", formData)
        .then(response => {
          console.log("Success!");
          console.log({ response });
        })
        .catch(error => {
          console.log({ error });
        });
    },
    submitDataVerify() {
      let formData = new FormData();

      // add message to form data
      formData.append("message", this.message);
      this.displayVerified = false;
      this.displayNotVerified = false;

      axios
        .post("http://127.0.0.1:5000/verification", formData)
        .then(response => {
          if (response.data === "True") {
            this.displayVerified = true;
          } else if (response.data === "False") {
            this.displayNotVerified = true;
          }
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