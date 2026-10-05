// The commands of test/run, in the order its index lists them. Each exports
// { name, summary, about, options, examples, run(args) -> exit code }.
module.exports = ['setup', 'unit', 'bench', 'matrix', 'ui', 'train', 'all'].map(name => require('./' + name));
