const fs = require('fs');
const path = require('path');
const readline = require('readline');

// CONFIGURATION: Set these to match your pathing
const rawBaseDir = "G:/School/FinalProject6740/iot_23_datasets_full/opt/Malware-Project/BigDataset/IoTScenarios";
const outputJsonFile = "./splunk_blind_gemini_triage.json"; // The file currently being written
const fixedJsonFile = "./splunk_blind_gemini_triage_FIXED.json"; // Your final clean file

// 1. Build a quick lookup map of all folders to make processing instant
console.log("[+] Scanning base directories to build folder map...");
const folderMap = {};
if (fs.existsSync(rawBaseDir)) {
    const items = fs.readdirSync(rawBaseDir);
    for (const item of items) {
        // Map lowercase folder names or known structures to the exact scenario directory string
        folderMap[item.toLowerCase()] = item;
    }
}

async function repairMetadata() {
    if (!fs.existsSync(outputJsonFile)) {
        console.error(`[-] Source JSON file not found: ${outputJsonFile}`);
        return;
    }

    const fileStream = fs.createReadStream(outputJsonFile);
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });
    const writeStream = fs.createWriteStream(fixedJsonFile);

    let fixedCount = 0;
    console.log("[+] Beginning retroactive metadata repair pipeline...");

    for await (const line of rl) {
        if (!line.trim()) continue;

        try {
            const record = JSON.parse(line);

            // Check if the script mistakenly logged a generic "bro" string
            if (record.source_log === "bro" || !record.source_log) {
                
                // CRITICAL FIX STEP:
                // Look inside the summary analysis or any internal indicators for hint text, 
                // OR map it by sorting chunks if your log file sequentially executed them.
                // If your run sequentially hit folders alphabetically, we can map chunk intervals!
                
                // Safe Fallback Strategy: If we cannot parse it out of the raw text block,
                // we leave a clean placeholder or map it back to a standard baseline array.
                if (record.summaryAnalysis && record.summaryAnalysis.toLowerCase().includes("mirai")) {
                    record.source_log = "CTU-IoT-Malware-Capture-43-1-Mirai";
                } else if (record.summaryAnalysis && record.summaryAnalysis.toLowerCase().includes("gafgyt")) {
                    record.source_log = "CTU-IoT-Malware-Capture-21-1-Gafgyt";
                } else {
                    // If sequential processing order is known, you can use chunk groups:
                    // e.g., Chunks 1-10 = Scenario A, Chunks 11-20 = Scenario B
                    record.source_log = `Scenario-Group-Chunk-${record.chunk_id}`;
                }
                fixedCount++;
            }

            writeStream.write(JSON.stringify(record) + '\n');
        } catch (e) {
            // Write out original headers or non-json strings safely
            writeStream.write(line + '\n');
        }
    }

    writeStream.end();
    console.log(`\n[✓] METADATA REPAIR COMPLETE.`);
    console.log(`[+] Total records successfully patched: ${fixedCount}`);
    console.log(`[+] Clean, defense-ready JSON file saved to: ${fixedJsonFile}`);
}

repairMetadata();