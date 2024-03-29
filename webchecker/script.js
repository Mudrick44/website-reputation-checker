const webchecker = document.getElementById("webcheckerinput");
const noticediv = document.getElementById("noticebanner");
const scanbutton = document.getElementById("scanbtn");
const loader = document.getElementById("loader-section");

// this function is to display the notice about writting the corect dns name
webchecker.addEventListener("input", function () {
  if (webchecker.value.trim() === "") {
    noticediv.style.display = "none";
  } else {
    noticediv.style.display = "flex";
  }
});

const options = {
  method: "GET",
  headers: {
    accept: "application/json",
    "x-apikey":
      "8a616b9618b3b01f1e2d7d8e3deaa80cee305dbdaf5062dff34740dcab105282",
  },
};

async function fetchwebinfo() {
  const webchecker = document.getElementById("webcheckerinput");
  const reportcontainer = document.getElementById("report-container");
  const loader = document.getElementById("loader-section");
  const resultscontainer = document.getElementById("result-container");
  const errorContainer = document.getElementById("error-container");

  // this is to display the loader when the user clicks the button
  loader.style.display = "flex";
  resultscontainer.style.display = "none";

  const domain = webchecker.value.trim();
  webchecker.value = "";

  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/domains/${domain}`,
      options
    );

    // Hide the loader immediately when the request completes
    loader.style.display = "none";

    if (response.ok) {
      const data = await response.json();
      let malicious = data.data.attributes.last_analysis_stats.malicious;
      let suspicious = data.data.attributes.last_analysis_stats.suspicious;
      let undetected = data.data.attributes.last_analysis_stats.undetected;
      let harmless = data.data.attributes.last_analysis_stats.harmless;
      let whois = data.data.attributes.whois;
      let whoisData = whois.split("\n");
      let jamcertificate = data.data.attributes.jarm;
      let signatureAlgorithm =
        data.data.attributes.last_https_certificate.cert_signature
          .signature_algorithm;
      let signature =
        data.data.attributes.last_https_certificate.cert_signature.signature;
      let domainId = data.data.id;
      let alphaEngine = data.data.attributes.categories[`alphaMountain.ai`];
      let sophos = data.data.attributes.categories.Sophos;
      let BitDefender = data.data.attributes.categories.BitDefender;
      let xcitium = data.data.attributes.categories["Xcitium Verdict Cloud"];
      let forcepoint =
        data.data.attributes.categories["Forcepoint ThreatSeeker"];
      let searchengines = data.data.attributes.last_analysis_results;
      console.log(searchengines);

      displaydata(
        malicious,
        suspicious,
        undetected,
        harmless,
        whoisData,
        jamcertificate,
        signatureAlgorithm,
        signature,
        domainId,
        alphaEngine,
        sophos,
        BitDefender,
        xcitium,
        forcepoint
      );
      populateTable(searchengines);
      maliciouscount(malicious);

      // Show the results container
      resultscontainer.style.display = "block";
      errorContainer.style.display = "none";
      reportcontainer.style.display = "flex";
    } else {
      reportcontainer.style.display = "none";
      errorContainer.style.display = "block";

      // Display error message to the user
      const errorMessage = await response.json();
      displayError(errorMessage.error.message);
    }
  } catch (error) {
    console.log(error);
    // Hide the loader immediately
    loader.style.display = "none";

    // this is to Display generic error message to the user
    displayError(
      "An error occurred while processing your request. Please try again later."
    );

    // Show error container
    reportcontainer.style.display = "none";
    errorContainer.style.display = "block";
  }

  function displaydata(
    malicious,
    suspicious,
    undetected,
    harmless,
    whoisData,
    jamcertificate,
    signatureAlgorithm,
    signature,
    domainId,
    alphaEngine,
    sophos,
    BitDefender,
    xcitium,
    forcepoint
  ) {
    const maliciousdiv = document.getElementById("malicious");
    maliciousdiv.textContent = malicious;

    const suspiciousdiv = document.getElementById("suspicious");
    suspiciousdiv.textContent = suspicious;

    const undetecteddiv = document.getElementById("undetected");
    undetecteddiv.textContent = undetected;

    const harmlessdiv = document.getElementById("harmless");
    harmlessdiv.textContent = harmless;

    const jarmcertificatediv = document.getElementById(
      "jarm-certificate-display"
    );
    jarmcertificatediv.textContent = jamcertificate;

    const signatureAlgorithmdiv = document.getElementById(
      "signature-algorithm-display"
    );
    signatureAlgorithmdiv.textContent = signatureAlgorithm;

    const signatureDiv = document.getElementById("signature-display");
    signatureDiv.textContent = signature;

    const domainIdDiv = document.getElementById("id-domain");
    domainIdDiv.textContent = domainId;

    const BitDefenderDiv = document.getElementById("BitDefender");
    BitDefenderDiv.textContent = BitDefender;

    const xcitiumdiv = document.getElementById("Xcitium");
    xcitiumdiv.textContent = xcitium;

    const alphaEngineDiv = document.getElementById("alphaMountainEngine");
    alphaEngineDiv.textContent = alphaEngine;

    const sophosDiv = document.getElementById("sophosEngine");
    sophosDiv.textContent = sophos;

    const forcepointDiv = document.getElementById("Forcepoint");
    forcepointDiv.textContent = forcepoint;

    const dnsdisplay = document.getElementById("dns-display");
    // Clear previous content
    dnsdisplay.innerHTML = "";

    // i created this to loop through each line of WHOIS data
    whoisData.forEach((line) => {
      // Split line into words
      const words = line.split(" ");
      // this is to create a new paragraph element
      const p = document.createElement("p");
      // Add padding to the paragraph
      p.style.padding = "5px";
      // Loop through each word in the line
      words.forEach((word, index) => {
        // Create a new span element for the word
        const span = document.createElement("span");
        // Make the first word bold
        if (index === 0) {
          span.innerHTML = `<strong>${word}</strong>`;
        } else {
          span.textContent = word;
        }
        // Append the word to the paragraph
        p.appendChild(span);
        // Add a space if it's not the last word
        if (index < words.length - 1) {
          p.appendChild(document.createTextNode(" "));
        }
      });
      // Append the paragraph to the container
      dnsdisplay.appendChild(p);
    });
  }
  // the purpose of this function to handle errors and display the error message
  function displayError(errorMessage) {
    const errorDiv = document.getElementById("error-container");
    errorDiv.className = "errorDiv";
    errorDiv.textContent = errorMessage;
    errorDiv.style.textAlign = "center";
    errorDiv.style.marginTop = "20px";
  }
  function populateTable(searchdata) {
    const tableBody = document.getElementById("data-table-body");
    tableBody.innerHTML = "";
    Object.values(searchdata).forEach((entry) => {
      const row = document.createElement("tr");
      const categoryCell = document.createElement("td");
      const resultCell = document.createElement("td");

      row.innerHTML = `
            <td>${entry.engine_name}</td>
            <td>${entry.category}</td>
            <td>${entry.result}</td>
        `;
      tableBody.appendChild(row);
    });
  }
  // this function is to display the count of malicious stats from security vendors
  function maliciouscount(malicious) {
    const maliciousNumber = document.getElementById("maliciousCount");
    const maliciousResultDiv = document.getElementById("resultDiv");
    maliciousNumber.textContent = malicious;
    if (malicious == "0") {
      maliciousResultDiv.style.display = "none";
    }
  }
}

scanbutton.addEventListener("click", fetchwebinfo);
