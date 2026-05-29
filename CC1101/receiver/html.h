
const char* HTML_HEADER = R"=====(
<!DOCTYPE html>
<html>
<head>
<title>minIFF Setup</title>
<meta name="viewport" content="width=device-width, initial-scale=0.7">
<style>
  body {
    font-size: 16px;
  }
  .user-input {
    margin-bottom: 20px;
  }
  .user-input input {
    flex: 1;
    border: 1px solid #444;
    padding: 5px;
  }
  .user-input input[type="submit"] {
    margin-left: 5px;
    background-color: #007bff;
    color: #fff;
    border: none;
    padding: 5px 10px;
    cursor: pointer;
  }
</style>
</head>
)=====";


const char* HTML_SETUP = R"=====(
<body>
    <h1>minIFF</h1>
    <h2>Setup Page</h2>
    <form class="user-input" action="/setup" method="GET">
      <label for="fname">RNG Seed:</label>
      <input type="text" id="seed" name="seed" placeholder="RNG seed"><br><br>
      <label for="fname">Drone private key:</label>
      <input type="text" id="sk" name="sk" placeholder="Drone secret key"><br><br>
      <label for="fname">Drone public key</label>
      <input type="text" id="pk" name="pk" placeholder="Drone public key"><br><br>
      <label for="fname">Drone id:</label>
      <input type="text" id="id" name="id" placeholder="Drone ID"><br><br>
      <label for="fname">Interrogator signature public key:</label>
      <input type="text" id="interr_sig_pk" name="interr_sig_pk" placeholder="Interrogator signature public key"><br><br>
      <label for="fname">Interrogator ecnryption public key:</label>
      <input type="text" id="interr_enc_pk" name="interr_enc_pk" placeholder="Interrogator encryption public key"><br><br>
      <input type="submit" value="Send">
    </form>
</body>
</html>
)=====";

const char* HTML_COMPLETED_SETUP = R"=====(
<body>
    <h1>minIFF</h1>
    <h2>Setup Page</h2>
    Setup succeeded. You can reset the controller and use the IFF receiver.
</body>
</html>
)=====";

const char* HTML_FAILED_SETUP = R"=====(
<body>
    <h1>minIFF</h1>
    <h2>Setup Page</h2>
    Failed setup, restart the whole process.
    <button onclick="window.location.href='/';">
      Back to setup
    </button>
</body>
</html>
)=====";
