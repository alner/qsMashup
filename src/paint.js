export default function paint($element, layout) {
  let element = ($element)[0];
  const main = require('./components/app');
  main($element, layout);
}
