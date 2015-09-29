export default function main($element, layout) {
  var React = require('react');
  var App = require('./app');

  console.log('*** paint ***');
  console.log($element, layout);
  React.render(<App layout={layout} />, ($element)[0]);
}
