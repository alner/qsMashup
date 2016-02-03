import Component from './base';
import Cell from './cell';
import TestDrag from './test';

export default class App extends Component {
  displayName: 'App'
  render() {
    // <Cell {...this.props}/>
    // <TestDrag />
    return (
      <div className="qv-object-markup">
        <Cell style={{width: "200px", height: "200px"}} {...this.props}/>
      </div>
    )
  }
}
