import React, { useState, useRef, useEffect } from "react";
import "./App.css";

function App() {
  const [output, setOutput] = useState("Welcome to the pSIONIUM Web Shell. Type 'help' for a list of commands.\n");
  const [input, setInput] = useState("");
  const terminalRef = useRef(null);

  const handleCommand = async (command) => {
    const args = command.split(" ");
    const cmd = args[0];
    const params = {};

    if (cmd === "encode" || cmd === "decode") {
      params.file = args[1];
      if (args[2] && args[2].startsWith("--type=")) {
        params.type = args[2].split("=")[1];
      }
    } else if (cmd === "compress" || cmd === "decompress") {
      params.file = args[1];
      if (args[2] && args[2].startsWith("--algorithm=")) {
        params.algorithm = args[2].split("=")[1];
      }
    }

    const response = await fetch("http://localhost:5000/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: cmd, args: params }),
    });
    const data = await response.json();
    setOutput((prev) => prev + `\n${data.output}\n`);
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter") {
      setOutput((prev) => prev + `\npSIONIUM> ${input}\n`);
      handleCommand(input);
      setInput("");
    }
  };

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [output]);

  return (
    <div className="terminal" ref={terminalRef}>
      <pre>{output}</pre>
      <div className="input-line">
        <span>pSIONIUM&gt; </span>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={handleKeyPress}
          autoFocus
        />
      </div>
    </div>
  );
}

export default App;