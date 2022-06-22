# Desafio Clase 32: Logs, profiling & debug (Parte II)

### 1.Asegurese de instalar los módulos correspondientes con el comando "npm i"
### 2.Iniciar proyecto con "node server.js"

### Consigna: LOGGERS, GZIP y ANÁLISIS DE PERFORMANCE

<ul>
<li>Se utilizo el modulo "compression" para la correspondiente compresion.</li>
<li>Se utilizo el modulo "pino" para realizar los loggeos y guardarlos en la capeta "logs".</li>
<li>En la carpeta "resultados_analisis" se encuentran los TXT con los resultados de los tests realizados con Artillery y Autocannon:</li>
    <ul>
        <li>Observando los archivos TXT "result_console_log_info" y "result_info" procesados con Artillery:</li>
            <ul>
            <li>Segun la media de response time podemos ver que se demoro mas con Console.log (response_time: 61) que sin usar el console.log (response_time: 22.9)</li>
            <li>Además el tiempo total fue de 4 seconds con Console.log contra 2 seconds SIN console.log.</li>
            </ul>
        <li>También se incluye captura de la consola utilizando Autocannon en línea de comandos, emulando 100 conexiones concurrentes realizadas
        en un tiempo de 20 segundos.</li>
        <li>Se incluye un archivo de Chrome (.CPUprofile) con el perfilamiento del servidor con el modo inspector.</li>
    </ul>
<li>Por último, en la carpeta "debug-0x" se incluye el HTML con el diagrama flama de 0x.</li>
</ul>
