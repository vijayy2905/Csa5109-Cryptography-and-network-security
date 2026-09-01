// ============================================================
// SECURE EHR FRONTEND
// ============================================================

let sampleData = null;


// ============================================================
// API HELPER
// ============================================================

async function api(url, options = {}) {

    const response = await fetch(
        url,
        options
    );

    return await response.json();
}


// ============================================================
// PAGE NAVIGATION
// ============================================================

function openPage(page) {

    document
        .querySelectorAll(".nav-button")
        .forEach(button => {

            button.classList.toggle(
                "active",
                button.dataset.page === page
            );

        });


    document
        .querySelectorAll(".page")
        .forEach(section => {

            section.classList.toggle(
                "active",
                section.id === page
            );

        });


    if (page === "sign") {
        loadSignSample();
    }

    if (page === "tamper") {
        loadTamperPage();
    }

    if (page === "hash") {
        loadHashAnalysis();
    }

    if (page === "signature") {
        loadSignatureAnalysis();
    }

    if (page === "tests") {
        loadTests();
    }
}


document
    .querySelectorAll(".nav-button")
    .forEach(button => {

        button.addEventListener(
            "click",
            () => openPage(
                button.dataset.page
            )
        );

    });


// ============================================================
// LOAD SAMPLE DATA
// ============================================================

async function getSample() {

    if (!sampleData) {

        sampleData = await api(
            "/api/sample"
        );

    }

    return sampleData;
}


// ============================================================
// SIGN PAGE
// ============================================================

async function loadSignSample() {

    const data = await getSample();

    const type =
        document.getElementById(
            "recordType"
        ).value;

    const documentData =
        type === "prescription"
            ? data.prescription
            : data.ehr;

    document.getElementById(
        "signInput"
    ).value = JSON.stringify(
        documentData,
        null,
        2
    );
}


document
    .getElementById("recordType")
    .addEventListener(
        "change",
        loadSignSample
    );


// ============================================================
// SIGN DOCUMENT
// ============================================================

async function signDocument() {

    try {

        const documentData =
            JSON.parse(
                document.getElementById(
                    "signInput"
                ).value
            );


        const scheme =
            document.getElementById(
                "scheme"
            ).value;


        const result =
            await api(
                "/api/sign",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        document:
                            documentData,

                        scheme:
                            scheme
                    })
                }
            );


        document.getElementById(
            "signOutput"
        ).textContent =
            JSON.stringify(
                result,
                null,
                2
            );


        document.getElementById(
            "verifyInput"
        ).value =
            JSON.stringify(
                result,
                null,
                2
            );


        alert(
            "EHR signed successfully. The secure envelope is ready for verification."
        );

    }

    catch (error) {

        alert(
            "Invalid JSON document. Please check the entered data."
        );

    }

}


// ============================================================
// VERIFY DOCUMENT
// ============================================================

async function verifyDocument() {

    try {

        const envelope =
            JSON.parse(
                document.getElementById(
                    "verifyInput"
                ).value
            );


        const result =
            await api(
                "/api/verify",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify(
                        envelope
                    )
                }
            );


        const accepted =
            result.outcome ===
            "ACCEPTED";


        const icon =
            document.getElementById(
                "verificationIcon"
            );


        const title =
            document.getElementById(
                "verificationTitle"
            );


        icon.textContent =
            accepted ? "✓" : "!";


        icon.style.background =
            accepted
                ? "#e8faf3"
                : "#fff0ef";


        icon.style.color =
            accepted
                ? "#18a874"
                : "#ef5b55";


        title.textContent =
            accepted
                ? "VERIFICATION SUCCESSFUL"
                : "TAMPERING DETECTED — REJECTED";


        document.getElementById(
            "digestResult"
        ).textContent =
            result.digest_match
                ? "TRUE"
                : "FALSE";


        document.getElementById(
            "signatureResult"
        ).textContent =
            result.signature_valid
                ? "TRUE"
                : "FALSE";


        document.getElementById(
            "outcomeResult"
        ).textContent =
            result.outcome;


    }

    catch (error) {

        alert(
            "Invalid secure envelope JSON."
        );

    }

}


// ============================================================
// HASH ANALYSIS
// ============================================================

async function loadHashAnalysis() {

    const rows =
        await api(
            "/api/hash-analysis"
        );


    const table =
        document.getElementById(
            "hashTable"
        );


    table.innerHTML = "";


    rows.forEach(row => {

        const legacy =
            row.algorithm === "MD5" ||
            row.algorithm === "SHA-1";


        const tr =
            document.createElement(
                "tr"
            );


        tr.innerHTML = `

            <td>
                <strong>
                    ${row.algorithm}
                </strong>
            </td>

            <td>
                ${row.bits}-bit
            </td>

            <td>
                ${row.time_us} µs
            </td>

            <td>
                ${row.avalanche_pct}%
            </td>

            <td class="${
                legacy
                    ? "bad"
                    : "good"
            }">

                ${
                    legacy
                        ? "Legacy / Exclude"
                        : "Modern Candidate"
                }

            </td>
        `;


        table.appendChild(tr);

    });

}


// ============================================================
// SIGNATURE ANALYSIS
// ============================================================

async function loadSignatureAnalysis() {

    const rows =
        await api(
            "/api/signature-analysis"
        );


    const container =
        document.getElementById(
            "signatureCards"
        );


    container.innerHTML = "";


    rows.forEach(row => {

        const card =
            document.createElement(
                "div"
            );


        card.className = "card";


        card.innerHTML = `

            <div class="card-heading">

                ${row.scheme}

            </div>


            <div class="signature-number">

                ${row.signature_bytes}

                <small>
                    bytes / signature
                </small>

            </div>


            <div class="info-row">

                <span>
                    Sign time
                </span>

                <b>
                    ${row.sign_ms} ms
                </b>

            </div>


            <div class="info-row">

                <span>
                    Verify time
                </span>

                <b>
                    ${row.verify_ms} ms
                </b>

            </div>


            <div class="info-row">

                <span>
                    Genuine record
                </span>

                <b class="good">

                    ${
                        row.genuine
                            ? "PASS"
                            : "FAIL"
                    }

                </b>

            </div>


            <div class="info-row">

                <span>
                    Tampered record
                </span>

                <b class="bad">

                    ${
                        row.tampered
                            ? "UNSAFE"
                            : "REJECTED"
                    }

                </b>

            </div>

        `;


        container.appendChild(card);

    });

}


// ============================================================
// TAMPER PAGE
// ============================================================

async function loadTamperPage() {

    const data =
        await getSample();


    document.getElementById(
        "originalRecord"
    ).textContent =
        data.ehr.diagnosis;


    const envelope =
        await api(
            "/api/sign",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    document:
                        data.ehr,

                    scheme:
                        "RSA-2048/PSS"
                })
            }
        );


    document.getElementById(
        "originalHash"
    ).textContent =
        envelope.sha256_digest;


    document.getElementById(
        "tamperedRecord"
    ).textContent =
        "Click the button below to simulate an attacker modification.";

}


// ============================================================
// SIMULATE TAMPERING
// ============================================================

async function simulateTampering() {

    const data =
        await getSample();


    const envelope =
        await api(
            "/api/sign",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    document:
                        data.ehr,

                    scheme:
                        "RSA-2048/PSS"
                })
            }
        );


    const modified =
        await api(
            "/api/tamper",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    document:
                        data.ehr
                })
            }
        );


    const modifiedEnvelope = {
        ...envelope,
        document: modified
    };


    const result =
        await api(
            "/api/verify",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify(
                    modifiedEnvelope
                )
            }
        );


    document.getElementById(
        "tamperedRecord"
    ).textContent =
        modified.diagnosis;


    document.getElementById(
        "tamperedHash"
    ).textContent =
        result.recomputed_digest;


    const resultBox =
        document.getElementById(
            "tamperResult"
        );


    resultBox.classList.remove(
        "hidden"
    );


    resultBox.innerHTML = `

        <strong>
            ❌ TAMPERING DETECTED
        </strong>

        <br><br>

        Digest Match:
        ${result.digest_match}

        &nbsp; | &nbsp;

        Signature Valid:
        ${result.signature_valid}

        &nbsp; | &nbsp;

        Outcome:
        ${result.outcome}

    `;

}


// ============================================================
// TEST RESULTS
// ============================================================

async function loadTests() {

    const rows =
        await api(
            "/api/tests"
        );


    const passed =
        rows.filter(
            row => row.pass
        ).length;


    document.getElementById(
        "testSummary"
    ).textContent =
        `${passed}/${rows.length} test cases passed`;


    const list =
        document.getElementById(
            "testList"
        );


    list.innerHTML = "";


    rows.forEach(row => {

        const item =
            document.createElement(
                "div"
            );


        item.className =
            "test-row";


        item.innerHTML = `

            <span>

                ${row.id}
                —
                ${row.name}

            </span>

            <span class="${
                row.pass
                    ? "pass"
                    : "bad"
            }">

                ${
                    row.pass
                        ? "PASS"
                        : "FAIL"
                }

            </span>

        `;


        list.appendChild(item);

    });

}


// ============================================================
// INITIAL LOAD
// ============================================================

loadSignSample();

loadHashAnalysis();
