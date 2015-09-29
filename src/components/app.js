import Component from './base';
import Cell from './cell';

export default class App extends Component {
  displayName: 'App'
  render() {
    return (
      <div className="qv-object-markup">
        <Cell {...this.props}/>
      </div>
    )
  }
}
