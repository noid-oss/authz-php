<?php

declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()->in([__DIR__ . '/src', __DIR__ . '/tests', __DIR__ . '/scripts']);

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@PER-CS2.0' => true,
        'declare_strict_types' => true,
        'strict_comparison' => true,
        'yoda_style' => ['equal' => true, 'identical' => true, 'less_and_greater' => false],
        'no_unused_imports' => true,
        'ordered_imports' => true,
    ])
    ->setFinder($finder);
