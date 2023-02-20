<?php

namespace HyveJWT\Console;

use HyveJWT\Generate;
use Exception;
use Illuminate\Console\Command;

class GenerateKeys extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'jwt:generate-keys';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create the encryption keys for JWT authentication';

    /**
     * Execute the console command.
     *
     * @return int
     * @throws Exception
     */
    public function handle()
    {
        Generate::provider('eddsa')->generateKeys();

        return 0;
    }
}
