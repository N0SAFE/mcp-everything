#!/usr/bin/env node
const { program } = require('commander');
const { spawn } = require('child_process');
const net = require('net');

/**
 * Checks if a port is in use
 * @param {number} port The port to check
 * @returns {Promise<boolean>} True if the port is in use, false otherwise
 */
function isPortInUse(port) {
    return new Promise((resolve) => {
        const server = net.createServer();
        
        server.once('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                resolve(true);
            } else {
                resolve(false);
            }
        });
        
        server.once('listening', () => {
            server.close();
            resolve(false);
        });
        
        server.listen(port);
    });
}

/**
 * Kills a process running on a specific port
 * @param {number} port The port to free
 * @returns {Promise<boolean>} True if a process was killed, false otherwise
 */
async function killProcessOnPort(port) {
    return new Promise((resolve) => {
        // This command is cross-platform compatible
        const command = process.platform === 'win32' 
            ? `netstat -ano | findstr :${port} | findstr LISTENING`
            : `lsof -i :${port} -t`;
        
        const findProcess = spawn(process.platform === 'win32' ? 'cmd.exe' : 'sh', 
            [process.platform === 'win32' ? '/c' : '-c', command]);
        
        let output = '';
        
        findProcess.stdout.on('data', (data) => {
            output += data.toString();
        });
        
        findProcess.on('close', (code) => {
            if (code !== 0 || !output.trim()) {
                return resolve(false);
            }
            
            let pid;
            if (process.platform === 'win32') {
                // Extract PID from the last column of netstat output
                const match = output.trim().split('\n')[0].trim().split(/\s+/).pop();
                if (match) pid = match;
            } else {
                // lsof directly returns the PID
                pid = output.trim().split('\n')[0];
            }
            
            if (!pid) return resolve(false);
            
            const killCmd = process.platform === 'win32'
                ? spawn('taskkill', ['/F', '/PID', pid])
                : spawn('kill', ['-9', pid]);
            
            killCmd.on('close', () => {
                resolve(true);
            });
        });
    });
}

/**
 * Kill a process with given PID
 * @param {number} pid Process ID to kill
 * @returns {Promise<boolean>} True if process was killed successfully
 */
async function killProcess(pid) {
    return new Promise((resolve) => {
        if (!pid) {
            return resolve(false);
        }
        
        const killCmd = process.platform === 'win32'
            ? spawn('taskkill', ['/F', '/PID', pid.toString()])
            : spawn('kill', ['-9', pid.toString()]);
        
        killCmd.on('close', (code) => {
            resolve(code === 0);
        });
    });
}

program
    .name('runThenKill')
    .description('Runs a process and manages port state after termination')
    .version('1.0.0')
    .requiredOption('-c, --command <command>', 'Command to run')
    .requiredOption('-p, --port <port>', 'Port to monitor', parseInt)
    .option('-a, --args <args...>', 'Arguments for the command')
    .option('-s, --secondary-command <command>', 'Secondary command to run if port is not open')
    .option('-sa, --secondary-args <args...>', 'Arguments for the secondary command')
    .action(async (options) => {
        const { command, port, args = [], secondaryCommand, secondaryArgs = [] } = options;
        
        console.log(`Checking if port ${port} is in use...`);
        const portWasInUse = await isPortInUse(port);
        console.log(`Port ${port} is${portWasInUse ? '' : ' not'} in use before starting the process.`);
        
        // Start secondary command if port is not in use and a secondary command was provided
        let secondaryProcess = null;
        if (!portWasInUse && secondaryCommand) {
            console.log(`Starting secondary process: ${secondaryCommand} ${secondaryArgs.join(' ')}`);
            
            // Split the command if it contains spaces and no args were provided
            const secondaryCommandParts = secondaryArgs.length > 0 ? 
                [secondaryCommand, ...secondaryArgs] : 
                secondaryCommand.split(/\s+/);
            
            const secondaryProcessToRun = secondaryCommandParts.shift();
            secondaryProcess = spawn(secondaryProcessToRun, secondaryCommandParts, {
                stdio: 'inherit',
                shell: true
            });
            
            console.log(`Secondary process started with PID: ${secondaryProcess.pid}`);
            
            // Wait a moment for the secondary process to start and potentially open the port
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
        
        console.log(`Starting main process: ${command} ${args.join(' ')}`);
        
        // Split the command if it contains spaces and no args were provided
        const commandParts = args.length > 0 ? [command, ...args] : command.split(/\s+/);
        const processToRun = commandParts.shift();
        const childProcess = spawn(processToRun, commandParts, { 
            stdio: 'inherit',
            shell: true
        });
        
        // Handle process termination
        childProcess.on('close', async (code) => {
            console.log(`Main process exited with code ${code}`);
            
            // Check current port state
            const portIsNowInUse = await isPortInUse(port);
            
            // Kill secondary process if it was started
            if (secondaryProcess && secondaryProcess.pid) {
                console.log('Terminating secondary process...');
                
                // First attempt to kill by PID
                const killed = await killProcess(secondaryProcess.pid);
                console.log(killed 
                    ? `Successfully killed secondary process with PID ${secondaryProcess.pid}` 
                    : `Failed to kill secondary process with PID ${secondaryProcess.pid}`);
                
                // Also kill any process on the port
                console.log(`Ensuring port ${port} is freed by killing any process using it...`);
                const portKilled = await killProcessOnPort(port);
                console.log(portKilled 
                    ? `Successfully killed process on port ${port}` 
                    : `No process found on port ${port} or failed to kill it`);
            }
            
            // Restore original state
            if (portWasInUse && !portIsNowInUse) {
                console.log(`The port ${port} was originally in use but is now free. Port state is not preserved.`);
            } else if (!portWasInUse && portIsNowInUse) {
                console.log(`The port ${port} was originally free but is now in use. Killing process on port...`);
                const killed = await killProcessOnPort(port);
                console.log(killed 
                    ? `Successfully killed process on port ${port}` 
                    : `No process found on port ${port} or failed to kill it`);
            } else {
                console.log(`Port ${port} state is preserved (${portIsNowInUse ? 'in use' : 'free'})`);
            }
        });
        
        // Handle SIGINT (Ctrl+C) to gracefully exit
        process.on('SIGINT', async () => {
            console.log('\nReceived SIGINT. Terminating processes...');
            childProcess.kill('SIGINT');
            
            if (secondaryProcess && secondaryProcess.pid) {
                console.log(`Killing secondary process with PID ${secondaryProcess.pid}...`);
                await killProcess(secondaryProcess.pid);
                
                // Also kill any process on the port
                console.log(`Ensuring port ${port} is freed...`);
                await killProcessOnPort(port);
            }
        });
    });

program.parse(process.argv);